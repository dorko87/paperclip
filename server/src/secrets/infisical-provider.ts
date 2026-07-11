import type { DeploymentMode } from "@paperclipai/shared";
import { unprocessable } from "../errors.js";
import type {
  PreparedSecretVersion,
  SecretProviderClientErrorCode,
  SecretProviderHealthCheck,
  SecretProviderModule,
  SecretProviderValidationResult,
  SecretProviderVaultRuntimeConfig,
} from "./types.js";
import { SecretProviderClientError } from "./types.js";

/**
 * Infisical secret provider (Universal-Auth).
 *
 * Phase 1a scope (KON-2693): descriptor, validateConfig, and a real healthCheck
 * (Universal-Auth login + authenticated list ping). Managed writes and runtime
 * resolution are intentionally stubbed for Phase 2 and the provider is gated
 * `coming_soon` at the service layer, so none of the stubbed operations are
 * reachable at runtime.
 *
 * Security invariants:
 *  - Universal-Auth credentials are bootstrapped ONLY from the server process
 *    environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET). They are never
 *    read from, or persisted into, the vault config (the shared credential
 *    blocklist plus a `.strict()` config schema enforce this).
 *  - The list ping returns only a secret COUNT. Secret values and the access
 *    token never leave the gateway boundary and are never placed in health
 *    details, warnings, or logs.
 */

const INFISICAL_PROVIDER_ID = "infisical" as const;
const INFISICAL_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_SECRET_PATH = "/";
const INFISICAL_RUNTIME_CREDENTIAL_WARNING =
  "Infisical Universal-Auth machine identity credentials (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET) must be provided to the Paperclip server runtime through the process environment; they are never stored in company_secrets or provider vault config.";

interface InfisicalResolvedConfig {
  siteUrl: string | null;
  projectId: string | null;
  environment: string | null;
  secretPath: string;
}

interface InfisicalCredentials {
  clientId: string;
  clientSecret: string;
}

interface InfisicalSession {
  accessToken: string;
  expiresIn: number | null;
  tokenType: string | null;
}

interface InfisicalListResult {
  /** Count only — secret values never cross this boundary. */
  count: number;
}

interface InfisicalGateway {
  login(input: {
    siteUrl: string;
    clientId: string;
    clientSecret: string;
  }): Promise<InfisicalSession>;
  listSecrets(input: {
    siteUrl: string;
    accessToken: string;
    projectId: string;
    environment: string;
    secretPath: string;
  }): Promise<InfisicalListResult>;
}

function asOptionalNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Normalize a configured site URL to an origin (no trailing slash / path). */
function normalizeSiteUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function joinUrl(siteUrl: string, path: string): string {
  return `${siteUrl.replace(/\/+$/, "")}${path}`;
}

function readInfisicalCredentials(): InfisicalCredentials | null {
  const clientId = process.env.INFISICAL_CLIENT_ID?.trim();
  const clientSecret = process.env.INFISICAL_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

function loadInfisicalConfig(): InfisicalResolvedConfig {
  return {
    siteUrl: normalizeSiteUrl(asOptionalNonEmptyString(process.env.INFISICAL_SITE_URL)),
    projectId: asOptionalNonEmptyString(process.env.INFISICAL_PROJECT_ID),
    environment: asOptionalNonEmptyString(process.env.INFISICAL_ENVIRONMENT),
    secretPath:
      asOptionalNonEmptyString(process.env.INFISICAL_SECRET_PATH) ?? DEFAULT_SECRET_PATH,
  };
}

function readProviderVaultConfig(
  input: SecretProviderVaultRuntimeConfig,
): InfisicalResolvedConfig {
  if (input.provider !== INFISICAL_PROVIDER_ID) {
    throw unprocessable("Infisical provider received a mismatched provider vault");
  }
  if (input.status === "disabled") {
    throw unprocessable("Infisical provider vault is disabled");
  }
  // NOTE: unlike managed providers, the health probe is allowed to run while the
  // vault status is `coming_soon`. `coming_soon` blocks runtime *resolution*
  // (handled at the service layer and by the Phase-2 stubs below), not the
  // read-only connectivity probe used to validate a saved vault config.
  return {
    siteUrl:
      normalizeSiteUrl(asOptionalNonEmptyString(input.config.siteUrl)) ??
      normalizeSiteUrl(asOptionalNonEmptyString(process.env.INFISICAL_SITE_URL)),
    projectId: asOptionalNonEmptyString(input.config.projectId),
    environment: asOptionalNonEmptyString(input.config.environment),
    secretPath: asOptionalNonEmptyString(input.config.secretPath) ?? DEFAULT_SECRET_PATH,
  };
}

function canLoadInfisicalConfig(): boolean {
  const config = loadInfisicalConfig();
  return Boolean(config.siteUrl) && readInfisicalCredentials() !== null;
}

function classifyInfisicalError(message: string): SecretProviderClientErrorCode {
  if (/401|Unauthorized|invalid.{0,20}credential|authentication failed/i.test(message)) {
    return "access_denied";
  }
  if (/403|Forbidden|AccessDenied|not authorized|permission/i.test(message)) return "access_denied";
  if (/404|NotFound|not found/i.test(message)) return "not_found";
  if (/409|Conflict|already exists/i.test(message)) return "conflict";
  if (/429|Throttl|TooManyRequests|rate.?limit/i.test(message)) return "throttled";
  if (/fetch failed|ECONN|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|network|timed? ?out|aborted/i.test(message)) {
    return "provider_unavailable";
  }
  if (/400|422|ValidationError|invalid request|bad request/i.test(message)) return "invalid_request";
  return "provider_error";
}

function infisicalSafeMessage(code: SecretProviderClientErrorCode): string {
  switch (code) {
    case "access_denied":
      return "Infisical denied the request. Check the Universal-Auth machine identity and its project access.";
    case "throttled":
      return "Infisical throttled the request. Wait and try again.";
    case "not_found":
      return "Infisical could not find the requested project, environment, or secret path.";
    case "conflict":
      return "Infisical reported a conflict for the requested secret.";
    case "invalid_request":
      return "Infisical rejected the request.";
    case "provider_unavailable":
      return "Infisical is unavailable right now.";
    case "provider_error":
    default:
      return "Infisical request failed.";
  }
}

function normalizeInfisicalError(operation: string, error: unknown): never {
  if (error instanceof SecretProviderClientError) throw error;
  const rawMessage = error instanceof Error ? error.message : String(error);
  const code = classifyInfisicalError(rawMessage);
  throw new SecretProviderClientError({
    code,
    provider: INFISICAL_PROVIDER_ID,
    operation,
    message: infisicalSafeMessage(code),
    rawMessage,
    cause: error,
  });
}

class InfisicalHttpGateway implements InfisicalGateway {
  private async readJson(response: Response): Promise<Record<string, unknown>> {
    const text = await response.text();
    if (!text) return {};
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return { message: text.slice(0, 200) };
    }
  }

  private throwFromResponse(operation: string, response: Response, body: Record<string, unknown>): never {
    const code = String(
      body.__type ?? body.code ?? body.error ?? response.statusText ?? "UnknownError",
    );
    const message = String(body.message ?? body.error ?? code);
    const rawMessage = `${response.status} ${code}: ${message}`;
    const clientCode = classifyInfisicalError(rawMessage);
    throw new SecretProviderClientError({
      code: clientCode,
      provider: INFISICAL_PROVIDER_ID,
      operation,
      message: infisicalSafeMessage(clientCode),
      status: response.status,
      rawMessage,
    });
  }

  async login(input: {
    siteUrl: string;
    clientId: string;
    clientSecret: string;
  }): Promise<InfisicalSession> {
    const response = await fetch(joinUrl(input.siteUrl, "/api/v1/auth/universal-auth/login"), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ clientId: input.clientId, clientSecret: input.clientSecret }),
      signal: AbortSignal.timeout(INFISICAL_REQUEST_TIMEOUT_MS),
    });
    const body = await this.readJson(response);
    if (!response.ok) this.throwFromResponse("login", response, body);
    const accessToken = asOptionalNonEmptyString(body.accessToken);
    if (!accessToken) {
      throw new SecretProviderClientError({
        code: "provider_error",
        provider: INFISICAL_PROVIDER_ID,
        operation: "login",
        message: infisicalSafeMessage("provider_error"),
        rawMessage: "Infisical login response did not include an access token",
      });
    }
    return {
      accessToken,
      expiresIn: numberOrNull(body.expiresIn),
      tokenType: asOptionalNonEmptyString(body.tokenType),
    };
  }

  async listSecrets(input: {
    siteUrl: string;
    accessToken: string;
    projectId: string;
    environment: string;
    secretPath: string;
  }): Promise<InfisicalListResult> {
    const url = new URL(joinUrl(input.siteUrl, "/api/v3/secrets/raw"));
    url.searchParams.set("workspaceId", input.projectId);
    url.searchParams.set("environment", input.environment);
    url.searchParams.set("secretPath", input.secretPath);
    const response = await fetch(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${input.accessToken}`,
        accept: "application/json",
      },
      signal: AbortSignal.timeout(INFISICAL_REQUEST_TIMEOUT_MS),
    });
    const body = await this.readJson(response);
    if (!response.ok) this.throwFromResponse("listSecrets", response, body);
    // Return only the count; secret material never crosses this boundary.
    const secrets = Array.isArray(body.secrets) ? body.secrets : [];
    return { count: secrets.length };
  }
}

export function createInfisicalProvider(options?: {
  config?: InfisicalResolvedConfig;
  gateway?: InfisicalGateway;
  credentials?: () => InfisicalCredentials | null;
}): SecretProviderModule {
  function resolveConfig(providerConfig?: SecretProviderVaultRuntimeConfig | null): InfisicalResolvedConfig {
    if (providerConfig) return readProviderVaultConfig(providerConfig);
    return options?.config ?? loadInfisicalConfig();
  }

  function resolveGateway(): InfisicalGateway {
    return options?.gateway ?? new InfisicalHttpGateway();
  }

  function resolveCredentials(): InfisicalCredentials | null {
    return options?.credentials ? options.credentials() : readInfisicalCredentials();
  }

  function comingSoon(operation: string): never {
    throw unprocessable(
      `Infisical provider ${operation} is not enabled yet (coming soon; runtime resolution and managed writes arrive in a later phase).`,
    );
  }

  async function validateConfig(input?: {
    deploymentMode?: DeploymentMode;
    strictMode?: boolean;
    providerConfig?: SecretProviderVaultRuntimeConfig | null;
  }): Promise<SecretProviderValidationResult> {
    const warnings: string[] = [];
    if (input?.deploymentMode === "authenticated" && input.strictMode !== true) {
      warnings.push("Strict secret mode should be enabled for authenticated deployments");
    }
    let config: InfisicalResolvedConfig | null = null;
    try {
      config = resolveConfig(input?.providerConfig);
    } catch {
      config = null;
    }
    if (!config?.siteUrl) {
      warnings.push(
        "Infisical site URL is not configured (set the vault siteUrl or INFISICAL_SITE_URL).",
      );
    }
    if (!resolveCredentials()) {
      warnings.push(
        "Infisical Universal-Auth credentials are not present in the server environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET).",
      );
    }
    return { ok: true, warnings };
  }

  function notReadyHealth(config: InfisicalResolvedConfig | null, missing: string[]): SecretProviderHealthCheck {
    return {
      provider: INFISICAL_PROVIDER_ID,
      status: "warn",
      message: `Infisical provider is not ready: missing ${missing.join(", ")}.`,
      warnings: [
        `Missing required Infisical configuration: ${missing.join(", ")}.`,
        INFISICAL_RUNTIME_CREDENTIAL_WARNING,
        "Runtime resolution stays disabled while the Infisical provider is coming soon.",
      ],
      details: {
        siteUrl: config?.siteUrl ?? null,
        projectId: config?.projectId ?? null,
        environment: config?.environment ?? null,
        secretPath: config?.secretPath ?? null,
        credentialsPresent: resolveCredentials() !== null,
        credentialSource: "server environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET)",
        authenticated: false,
      },
    };
  }

  async function healthCheck(input?: {
    deploymentMode?: DeploymentMode;
    strictMode?: boolean;
    providerConfig?: SecretProviderVaultRuntimeConfig | null;
  }): Promise<SecretProviderHealthCheck> {
    let config: InfisicalResolvedConfig;
    try {
      config = resolveConfig(input?.providerConfig);
    } catch (error) {
      return notReadyHealth(null, [error instanceof Error ? error.message : String(error)]);
    }

    const credentials = resolveCredentials();
    const missing: string[] = [];
    if (!config.siteUrl) missing.push("siteUrl (INFISICAL_SITE_URL or vault siteUrl)");
    if (!credentials) missing.push("INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET");
    if (!config.siteUrl || !credentials) {
      return notReadyHealth(config, missing);
    }

    const validation = await validateConfig(input);
    const warnings = [...validation.warnings];

    try {
      const gateway = resolveGateway();
      const session = await gateway.login({
        siteUrl: config.siteUrl,
        clientId: credentials.clientId,
        clientSecret: credentials.clientSecret,
      });

      let listedSecretCount: number | null = null;
      if (config.projectId && config.environment) {
        try {
          const listed = await gateway.listSecrets({
            siteUrl: config.siteUrl,
            accessToken: session.accessToken,
            projectId: config.projectId,
            environment: config.environment,
            secretPath: config.secretPath,
          });
          listedSecretCount = listed.count;
        } catch (error) {
          // Login succeeded but the project/environment/path listing failed.
          // Surface as a warning with a safe message; never leak raw details.
          const safe =
            error instanceof SecretProviderClientError
              ? error.message
              : "Infisical secret listing failed for the configured project/environment/path.";
          warnings.push(safe);
        }
      } else {
        warnings.push(
          "Set projectId and environment to verify project access; only Universal-Auth login was checked.",
        );
      }

      return {
        provider: INFISICAL_PROVIDER_ID,
        status: warnings.length > 0 ? "warn" : "ok",
        message:
          "Infisical Universal-Auth login succeeded; the machine identity is reachable from the server runtime.",
        warnings,
        details: {
          siteUrl: config.siteUrl,
          projectId: config.projectId,
          environment: config.environment,
          secretPath: config.secretPath,
          authenticated: true,
          listedSecretCount,
          credentialSource: "server environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET)",
        },
        backupGuidance: [
          "Infisical is an external source of truth; back up the Infisical instance separately from Paperclip metadata.",
          "Restoring access requires the Paperclip database plus a valid Universal-Auth identity for the same Infisical project.",
        ],
      };
    } catch (error) {
      const code =
        error instanceof SecretProviderClientError ? error.code : classifyInfisicalError(String(error));
      const safe =
        error instanceof SecretProviderClientError ? error.message : infisicalSafeMessage(code);
      return {
        provider: INFISICAL_PROVIDER_ID,
        status: "error",
        message: safe,
        warnings: [
          INFISICAL_RUNTIME_CREDENTIAL_WARNING,
          "Infisical Universal-Auth login failed; verify the site URL, machine identity, and network reachability.",
        ],
        details: {
          siteUrl: config.siteUrl,
          projectId: config.projectId,
          environment: config.environment,
          secretPath: config.secretPath,
          authenticated: false,
          errorCode: code,
          credentialSource: "server environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET)",
        },
      };
    }
  }

  return {
    id: INFISICAL_PROVIDER_ID,
    descriptor() {
      return {
        id: INFISICAL_PROVIDER_ID,
        label: "Infisical",
        requiresExternalRef: true,
        supportsManagedValues: false,
        supportsExternalReferences: true,
        configured: canLoadInfisicalConfig(),
      };
    },
    validateConfig,
    // ---- Phase 2 (stubbed; unreachable while gated `coming_soon`) ----
    async createSecret(): Promise<PreparedSecretVersion> {
      return comingSoon("managed secret create");
    },
    async createVersion(): Promise<PreparedSecretVersion> {
      return comingSoon("managed secret version create");
    },
    async linkExternalSecret(): Promise<PreparedSecretVersion> {
      return comingSoon("external secret link");
    },
    async resolveVersion(): Promise<string> {
      return comingSoon("runtime resolution");
    },
    async deleteOrArchive(): Promise<void> {
      comingSoon("delete/archive");
    },
    healthCheck,
  };
}

export const infisicalProvider = createInfisicalProvider();
