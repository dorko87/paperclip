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

describe("infisicalProvider (Phase 1a skeleton)", () => {
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
      },
    });

    const health = await provider.healthCheck();
    expect(health.status).toBe("warn");
    expect(health.details?.authenticated).toBe(true);
    expect(health.warnings?.some((w) => /could not find/i.test(w))).toBe(true);
  });

  it("healthCheck runs against a coming_soon vault config (probe is allowed while gated)", async () => {
    const providerConfig: SecretProviderVaultRuntimeConfig = {
      id: "vault-1",
      provider: "infisical",
      status: "coming_soon",
      config: { ...CONFIG },
    };
    const provider = createInfisicalProvider({
      credentials: () => ({ ...CREDENTIALS }),
      gateway: {
        async login() {
          return { accessToken: "t", expiresIn: null, tokenType: null };
        },
        async listSecrets() {
          return { count: 1 };
        },
      },
    });
    const health = await provider.healthCheck({ providerConfig });
    expect(health.status).toBe("ok");
    expect(health.details?.authenticated).toBe(true);
  });

  it("Phase-2 runtime operations remain stubbed as coming soon", async () => {
    const provider = createInfisicalProvider({ config: { ...CONFIG } });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: "x" }),
    ).rejects.toThrow(/coming soon/i);
    await expect(
      provider.createSecret({ value: "v" }),
    ).rejects.toThrow(/coming soon/i);
  });
});
