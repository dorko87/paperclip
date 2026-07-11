import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createInfisicalProvider } from "../secrets/infisical-provider.js";
import { SecretProviderClientError } from "../secrets/types.js";
import type { SecretProviderVaultRuntimeConfig } from "../secrets/types.js";

const CONFIG = {
  siteUrl: "http://192.168.1.137:8081",
  projectId: "homelab-stacks",
  environment: "prod",
  secretPath: "/",
} as const;

const CREDENTIALS = { clientId: "machine-id", clientSecret: "machine-secret" };

const PINNED_SITE_URL = "http://192.168.1.137:8081";

/** Build a per-company vault config (projectId/environment come from here). */
function vaultConfig(
  overrides?: Partial<SecretProviderVaultRuntimeConfig["config"]>,
  status: string = "ready",
): SecretProviderVaultRuntimeConfig {
  return {
    id: "vault-1",
    provider: "infisical",
    status,
    config: {
      projectId: CONFIG.projectId,
      environment: CONFIG.environment,
      secretPath: CONFIG.secretPath,
      ...overrides,
    },
  };
}

describe("infisicalProvider (Phase 1b: reference resolution)", () => {
  const previousEnv = {
    INFISICAL_CLIENT_ID: process.env.INFISICAL_CLIENT_ID,
    INFISICAL_CLIENT_SECRET: process.env.INFISICAL_CLIENT_SECRET,
    INFISICAL_SITE_URL: process.env.INFISICAL_SITE_URL,
    INFISICAL_PROJECT_ID: process.env.INFISICAL_PROJECT_ID,
    INFISICAL_ENVIRONMENT: process.env.INFISICAL_ENVIRONMENT,
    INFISICAL_SECRET_PATH: process.env.INFISICAL_SECRET_PATH,
  };

  beforeEach(() => {
    // Deterministic: no ambient Infisical env for the "not ready" assertions.
    for (const key of Object.keys(previousEnv)) delete process.env[key];
  });

  afterEach(() => {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("exposes an external-reference descriptor gated until configured", () => {
    const provider = createInfisicalProvider();
    const descriptor = provider.descriptor();
    expect(descriptor.id).toBe("infisical");
    expect(descriptor.label).toBe("Infisical");
    expect(descriptor.requiresExternalRef).toBe(true);
    expect(descriptor.supportsManagedValues).toBe(false);
    expect(descriptor.supportsExternalReferences).toBe(true);
    // No env credentials/site URL provisioned in this test → not configured.
    expect(descriptor.configured).toBe(false);
  });

  it("validateConfig reports missing site URL and credentials without failing", async () => {
    const provider = createInfisicalProvider({ credentials: () => null });
    const result = await provider.validateConfig();
    expect(result.ok).toBe(true);
    expect(result.warnings.some((w) => /site URL/i.test(w))).toBe(true);
    expect(result.warnings.some((w) => /Universal-Auth credentials/i.test(w))).toBe(true);
  });

  it("validateConfig warns that a per-company siteUrl override is ignored (SEC-1)", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const provider = createInfisicalProvider({ credentials: () => ({ ...CREDENTIALS }) });
    const result = await provider.validateConfig({
      providerConfig: vaultConfig({ siteUrl: "http://evil.example.com" }),
    });
    expect(result.ok).toBe(true);
    expect(result.warnings.some((w) => /pinned server-side/i.test(w))).toBe(true);
  });

  it("healthCheck returns a not-ready warning (never throws) when credentials are absent", async () => {
    const provider = createInfisicalProvider({
      config: { ...CONFIG },
      credentials: () => null,
      gateway: {
        async login() {
          throw new Error("login must not be attempted without credentials");
        },
        async listSecrets() {
          throw new Error("listSecrets must not be attempted without credentials");
        },
        async readSecret() {
          throw new Error("readSecret must not be attempted without credentials");
        },
      },
    });
    const health = await provider.healthCheck();
    expect(health.provider).toBe("infisical");
    expect(health.status).toBe("warn");
    expect(health.details?.authenticated).toBe(false);
    expect(health.warnings?.some((w) => /INFISICAL_CLIENT_ID/.test(w))).toBe(true);
  });

  it("healthCheck performs a real Universal-Auth login + list ping and never leaks secret values", async () => {
    const loginCalls: Array<{ siteUrl: string; clientId: string; clientSecret: string }> = [];
    const listCalls: Array<Record<string, string>> = [];
    const provider = createInfisicalProvider({
      config: { ...CONFIG },
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login(input) {
          loginCalls.push(input);
          return { accessToken: "ephemeral-token", expiresIn: 3600, tokenType: "Bearer" };
        },
        async listSecrets(input) {
          listCalls.push(input);
          // Gateway boundary returns COUNT only — values never reach the provider.
          return { count: 4 };
        },
        async readSecret() {
          throw new Error("readSecret must not be attempted during healthCheck");
        },
      },
    });

    const health = await provider.healthCheck();
    expect(health.status).toBe("ok");
    expect(health.details?.authenticated).toBe(true);
    expect(health.details?.listedSecretCount).toBe(4);
    expect(loginCalls).toHaveLength(1);
    expect(loginCalls[0].clientId).toBe(CREDENTIALS.clientId);
    expect(listCalls[0]?.projectId).toBe(CONFIG.projectId);

    // The access token and any secret material must never appear in the report.
    const serialized = JSON.stringify(health);
    expect(serialized).not.toContain("ephemeral-token");
    expect(serialized).not.toContain(CREDENTIALS.clientSecret);
  });

  it("healthCheck reports error with a safe message when login fails", async () => {
    const provider = createInfisicalProvider({
      config: { ...CONFIG },
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          throw new SecretProviderClientError({
            code: "access_denied",
            provider: "infisical",
            operation: "login",
            message: "Infisical denied the request. Check the Universal-Auth machine identity and its project access.",
            rawMessage: "401 Unauthorized: bad client secret",
          });
        },
        async listSecrets() {
          return { count: 0 };
        },
        async readSecret() {
          return "unused";
        },
      },
    });

    const health = await provider.healthCheck();
    expect(health.status).toBe("error");
    expect(health.details?.authenticated).toBe(false);
    expect(health.details?.errorCode).toBe("access_denied");
    // Raw upstream detail must not leak into the user-facing report.
    expect(JSON.stringify(health)).not.toContain("bad client secret");
  });

  it("healthCheck warns (not errors) when login succeeds but listing fails", async () => {
    const provider = createInfisicalProvider({
      config: { ...CONFIG },
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          throw new SecretProviderClientError({
            code: "not_found",
            provider: "infisical",
            operation: "listSecrets",
            message: "Infisical could not find the requested project, environment, or secret path.",
            rawMessage: "404 NotFound",
          });
        },
        async readSecret() {
          return "unused";
        },
      },
    });

    const health = await provider.healthCheck();
    expect(health.status).toBe("warn");
    expect(health.details?.authenticated).toBe(true);
    expect(health.warnings?.some((w) => /could not find/i.test(w))).toBe(true);
  });

  it("healthCheck runs against a coming_soon vault config with the pinned origin", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 1 };
        },
        async readSecret() {
          return "unused";
        },
      },
    });
    const health = await provider.healthCheck({ providerConfig: vaultConfig(undefined, "coming_soon") });
    expect(health.status).toBe("ok");
    expect(health.details?.authenticated).toBe(true);
    expect(health.details?.siteUrl).toBe(PINNED_SITE_URL);
  });

  // ---- Phase 1b behaviour ----

  it("managed writes are unsupported (reference-only provider)", async () => {
    const provider = createInfisicalProvider({ config: { ...CONFIG } });
    await expect(provider.createSecret({ value: "v" })).rejects.toThrow(/reference-only|not supported/i);
    await expect(provider.createVersion({ value: "v" })).rejects.toThrow(/reference-only|not supported/i);
  });

  it("resolveVersion requires a per-company vault (isolation) and env credentials", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 0 };
        },
        async readSecret() {
          return "should-not-be-reached";
        },
      },
    });
    // No providerConfig → no per-company scope → refuse (no ambient resolution).
    await expect(
      provider.resolveVersion({ material: {}, externalRef: "API_KEY" }),
    ).rejects.toThrow(/provider vault/i);
  });

  it("linkExternalSecret validates the reference and stores coordinates, never the value", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const readCalls: Array<Record<string, string>> = [];
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 0 };
        },
        async readSecret(input) {
          readCalls.push(input);
          return "super-secret-value";
        },
      },
    });
    const prepared = await provider.linkExternalSecret({
      externalRef: "OPENAI_API_KEY",
      providerConfig: vaultConfig(),
    });
    // Validation read the referenced secret against the pinned origin + vault scope.
    expect(readCalls).toHaveLength(1);
    expect(readCalls[0].siteUrl).toBe(PINNED_SITE_URL);
    expect(readCalls[0].projectId).toBe(CONFIG.projectId);
    expect(readCalls[0].secretKey).toBe("OPENAI_API_KEY");
    // Persisted material stores the reference, not the value.
    expect(prepared.externalRef).toBe("infisical:///#OPENAI_API_KEY");
    const serialized = JSON.stringify(prepared);
    expect(serialized).not.toContain("super-secret-value");
    expect((prepared.material as Record<string, unknown>).secretKey).toBe("OPENAI_API_KEY");
  });

  it("resolveVersion reads the value against the pinned origin, ignoring a hostile vault siteUrl (SEC-1)", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const loginCalls: Array<{ siteUrl: string }> = [];
    const readCalls: Array<Record<string, string>> = [];
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login(input) {
          loginCalls.push(input);
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 0 };
        },
        async readSecret(input) {
          readCalls.push(input);
          return "resolved-value-123";
        },
      },
    });
    const value = await provider.resolveVersion({
      material: { scheme: "infisical", source: "external_reference", secretPath: "/svc", secretKey: "DB_PASSWORD" },
      externalRef: "infisical:///svc#DB_PASSWORD",
      providerConfig: vaultConfig({ siteUrl: "http://attacker.example.com" }),
    });
    expect(value).toBe("resolved-value-123");
    // Both the login and the read must go to the pinned origin, never the hostile one.
    expect(loginCalls[0].siteUrl).toBe(PINNED_SITE_URL);
    expect(readCalls[0].siteUrl).toBe(PINNED_SITE_URL);
    expect(readCalls[0].secretPath).toBe("/svc");
    expect(readCalls[0].secretKey).toBe("DB_PASSWORD");
  });

  it("resolveVersion surfaces a safe not_found when the referenced secret is missing", async () => {
    process.env.INFISICAL_SITE_URL = PINNED_SITE_URL;
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 0 };
        },
        async readSecret() {
          throw new SecretProviderClientError({
            code: "not_found",
            provider: "infisical",
            operation: "readSecret",
            message: "Infisical could not find the requested project, environment, or secret path.",
            rawMessage: "404 NotFound: secret GONE_KEY",
          });
        },
      },
    });
    await expect(
      provider.resolveVersion({
        material: { scheme: "infisical", source: "external_reference", secretPath: "/", secretKey: "GONE_KEY" },
        externalRef: "infisical:///#GONE_KEY",
        providerConfig: vaultConfig(),
      }),
    ).rejects.toMatchObject({ code: "not_found" });
  });
});
