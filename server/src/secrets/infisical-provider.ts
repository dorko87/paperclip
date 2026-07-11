import { createHash } from "node:crypto";
import type { DeploymentMode } from "@paperclipai/shared";
import { unprocessable } from "../errors.js";
import type {
  PreparedSecretVersion,
  SecretProviderClientErrorCode,
  SecretProviderHealthCheck,
  SecretProviderModule,
  SecretProviderValidationResult,
  SecretProviderVaultRuntimeConfig,
  StoredSecretVersionMaterial,
} from "./types.js";
import { SecretProviderClientError } from "./types.js";

/**
 * Infisical secret provider (Universal-Auth).
 *
 * Phase 1b scope (KON-2806): the provider is a usable *reference* provider.
 * Users link an existing Infisical secret by reference and Paperclip resolves
 * the value at runtime through the standard resolver (version rows, bindings,
 * per-company ownership asserts, and the audit log all sit in front of this).
 * Paperclip never writes into Infisical, so managed create/version/rotate are
 * unsupported and `supportsManagedValues` stays `false`.
 *
 * Live operations: descriptor, validateConfig, healthCheck (Universal-Auth
 * login + authenticated list ping), linkExternalSecret (validate the referenced
 * secret exists, store the reference — never the value), and resolveVersion
 * (read the value via the v3 raw route and return it to the resolver).
 *
 * Security invariants:
 *  - Universal-Auth credentials are bootstrapped ONLY from the server process
 *    environment (INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET). They are never
 *    read from, or persisted into, the vault config (the shared credential
 *    blocklist plus a `.strict()` config schema enforce this).
 *  - SEC-1 (KON-2697): the Infisical origin is PINNED server-side to the
 *    `INFISICAL_SITE_URL` env var. Per-company vault config MUST NOT override
 *    the origin — every authenticated request (login, list, read) goes to the
 *    pinned origin only, so a hostile per-company `siteUrl` can never be used to
 *    exfiltrate the global machine-identity credentials via SSRF.
 *  - The list ping returns only a secret COUNT and resolved values are returned
 *    straight to the resolver; secret material and the access token never enter
 *    health details, warnings, logs, or link-time metadata.
 */

const INFISICAL_PROVIDER_ID = "infisical" as const;
const INFISICAL_REF_SCHEME = "infisical" as const;
const INFISICAL_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_SECRET_PATH = "/";
const INFISICAL_SECRET_KEY_RE = /^[A-Za-z0-9_.-]+$/;
const INFISICAL_SECRET_PATH_RE = /^\/(?:[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*)?$/;
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

/** Parsed Infisical reference: a single secret within the vault's project/env. */
interface InfisicalSecretRef {
  secretPath: string;
  secretKey: string;
}

interface InfisicalReadInput {
  siteUrl: string;
  accessToken: string;
  projectId: string;
  environment: string;
  secretPath: string;
  secretKey: string;
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
  /** Read a single secret value via the v3 raw route. The value is returned to
   *  the resolver and MUST NOT be logged or placed in metadata. */
  readSecret(input: InfisicalReadInput): Promise<string>;
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

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * SEC-1 (KON-2697): the Infisical origin is pinned to the server env var
 * `INFISICAL_SITE_URL`. Per-company vault config never contributes the origin
 * used for authenticated requests, so a hostile per-company `siteUrl` cannot be
 * used to exfiltrate the global machine-identity credentials via SSRF.
 */
function pinnedSiteUrl(): string | null {
  return normalizeSiteUrl(asOptionalNonEmptyString(process.env.INFISICAL_SITE_URL));
}

function normalizeSecretPath(value: string | null | undefined): string {
  const trimmed = asOptionalNonEmptyString(value);
  if (!trimmed) return DEFAULT_SECRET_PATH;
  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  // Collapse any trailing slash except for the root path.
  const normalized = withLeadingSlash.length > 1
    ? withLeadingSlash.replace(/\/+$/, "")
    : withLeadingSlash;
  return normalized.length > 0 ? normalized : DEFAULT_SECRET_PATH;
}

/**
 * Parse the user-supplied external reference into an Infisical (path, key) pair.
 * Accepted forms (project + environment always come from the per-company vault
 * config, never the reference):
 *   - `infisical://<secretPath>#<secretKey>`  (canonical, round-trips from link)
 *   - `<secretPath>#<secretKey>`
 *   - `<secretKey>`  (path defaults to the vault config `secretPath`)
 */
function parseInfisicalRef(
  externalRef: string | null | undefined,
  defaultPath: string,
): InfisicalSecretRef {
  const raw = asOptionalNonEmptyString(externalRef);
  if (!raw) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: INFISICAL_PROVIDER_ID,
      operation: "parseRef",
      message: "An Infisical secret reference (secret key, or <path>#<key>) is required.",
      rawMessage: "Infisical external reference is empty",
    });
  }
  let body = raw;
  if (body.startsWith(`${INFISICAL_REF_SCHEME}://`)) {
    body = body.slice(`${INFISICAL_REF_SCHEME}://`.length);
  }
  const hashIndex = body.lastIndexOf("#");
  let secretPath: string;
  let secretKey: string;
  if (hashIndex >= 0) {
    secretPath = normalizeSecretPath(body.slice(0, hashIndex));
    secretKey = body.slice(hashIndex + 1).trim();
  } else {
    secretPath = normalizeSecretPath(defaultPath);
    secretKey = body.trim();
  }
  if (!secretKey || !INFISICAL_SECRET_KEY_RE.test(secretKey)) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: INFISICAL_PROVIDER_ID,
      operation: "parseRef",
      message: "The Infisical secret key is missing or contains unsupported characters.",
      rawMessage: "Infisical secret key failed validation",
    });
  }
  if (!INFISICAL_SECRET_PATH_RE.test(secretPath)) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: INFISICAL_PROVIDER_ID,
      operation: "parseRef",
      message: "The Infisical secret path must be an absolute path like /.",
      rawMessage: "Infisical secret path failed validation",
    });
  }
  return { secretPath, secretKey };
}

/** Canonical, storable external reference string for a parsed secret ref. */
function formatInfisicalRef(ref: InfisicalSecretRef): string {
  return `${INFISICAL_REF_SCHEME}://${ref.secretPath}#${ref.secretKey}`;
}

interface InfisicalStoredMaterial extends StoredSecretVersionMaterial {
  scheme: typeof INFISICAL_REF_SCHEME;
  source: "external_reference";
  secretPath: string;
  secretKey: string;
  projectId: string | null;
  environment: string | null;
}

function asInfisicalMaterial(material: StoredSecretVersionMaterial | null | undefined): {
  secretPath: string | null;
  secretKey: string | null;
} {
  if (!material || typeof material !== "object") return { secretPath: null, secretKey: null };
  const record = material as Record<string, unknown>;
  return {
    secretPath: asOptionalNonEmptyString(record.secretPath),
    secretKey: asOptionalNonEmptyString(record.secretKey),
  };
}

/**
 * Build the persisted version material for a linked external reference. Only the
 * reference coordinates are stored; the secret value is NEVER persisted (fetched
 * fresh at resolve time). `valueSha256` is a fingerprint of the reference, not
 * of the value.
 */
function buildExternalReferenceMaterial(
  config: InfisicalResolvedConfig,
  ref: InfisicalSecretRef,
): PreparedSecretVersion {
  const externalRef = formatInfisicalRef(ref);
  const fingerprint = sha256Hex(
    `${INFISICAL_REF_SCHEME}:${config.projectId ?? ""}:${config.environment ?? ""}:${ref.secretPath}:${ref.secretKey}`,
  );
  const material: InfisicalStoredMaterial = {
    scheme: INFISICAL_REF_SCHEME,
    source: "external_reference",
    secretPath: ref.secretPath,
    secretKey: ref.secretKey,
    projectId: config.projectId,
    environment: config.environment,
  };
  return {
    material,
    valueSha256: fingerprint,
    fingerprintSha256: fingerprint,
    externalRef,
    providerVersionRef: null,
  };
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
    // SEC-1: origin is pinned to INFISICAL_SITE_URL server-side. A per-company
    // `siteUrl` in the vault config is intentionally IGNORED for the origin so a
    // hostile value can never redirect authenticated (credential-bearing)
    // requests. Mismatches are surfaced as a validation warning, not honored.
    siteUrl: pinnedSiteUrl(),
    projectId: asOptionalNonEmptyString(input.config.projectId),
    environment: asOptionalNonEmptyString(input.config.environment),
    secretPath: normalizeSecretPath(asOptionalNonEmptyString(input.config.secretPath)),
  };
}

/** True when the vault config carries a `siteUrl` whose origin differs from the
 *  server-pinned origin (SEC-1). Used only to surface a validation warning. */
function vaultSiteUrlOverrideIgnored(input: SecretProviderVaultRuntimeConfig): boolean {
  const configured = normalizeSiteUrl(asOptionalNonEmptyString(input.config.siteUrl));
  if (!configured) return false;
  return configured !== pinnedSiteUrl();
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

  async readSecret(input: InfisicalReadInput): Promise<string> {
    // v3 raw single-secret route: GET /api/v3/secrets/raw/{secretKey}
    //   ?workspaceId=<projectId>&environment=<slug>&secretPath=<path>
    const url = new URL(
      joinUrl(input.siteUrl, `/api/v3/secrets/raw/${encodeURIComponent(input.secretKey)}`),
    );
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
    if (!response.ok) this.throwFromResponse("readSecret", response, body);
    const secret =
      body.secret && typeof body.secret === "object"
        ? (body.secret as Record<string, unknown>)
        : null;
    const secretValue = secret ? secret.secretValue : undefined;
    if (typeof secretValue !== "string") {
      throw new SecretProviderClientError({
        code: "not_found",
        provider: INFISICAL_PROVIDER_ID,
        operation: "readSecret",
        message: infisicalSafeMessage("not_found"),
        rawMessage: "Infisical read response did not include a string secret value",
      });
    }
    // The value is returned straight to the resolver; never logged here.
    return secretValue;
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

  function managedUnsupported(operation: string): never {
    throw unprocessable(
      `Infisical is a reference-only provider: ${operation} is not supported. Link an existing Infisical secret by reference instead (Paperclip never writes into Infisical).`,
    );
  }

  /**
   * Assemble everything needed for a credential-bearing operation (link/resolve).
   * Enforces per-company isolation and SEC-1:
   *  - a per-company vault `providerConfig` is REQUIRED (no global-env fallback
   *    for projectId/environment, so one company can never resolve against
   *    another company's — or an ambient — Infisical scope);
   *  - the origin is the server-pinned `INFISICAL_SITE_URL`;
   *  - Universal-Auth credentials come from the server env only.
   */
  function requireResolutionContext(
    operation: string,
    providerConfig: SecretProviderVaultRuntimeConfig | null | undefined,
  ): { config: InfisicalResolvedConfig; credentials: InfisicalCredentials; gateway: InfisicalGateway } {
    if (!providerConfig) {
      throw new SecretProviderClientError({
        code: "invalid_request",
        provider: INFISICAL_PROVIDER_ID,
        operation,
        message: "An Infisical provider vault (project + environment) must be selected for this company.",
        rawMessage: "Infisical resolution requires a per-company provider vault config",
      });
    }
    const config = readProviderVaultConfig(providerConfig);
    const missing: string[] = [];
    if (!config.siteUrl) missing.push("INFISICAL_SITE_URL");
    if (!config.projectId) missing.push("projectId");
    if (!config.environment) missing.push("environment");
    if (missing.length > 0) {
      throw new SecretProviderClientError({
        code: "invalid_request",
        provider: INFISICAL_PROVIDER_ID,
        operation,
        message: `Infisical vault is missing required configuration: ${missing.join(", ")}.`,
        rawMessage: `Infisical resolution missing: ${missing.join(", ")}`,
      });
    }
    const credentials = resolveCredentials();
    if (!credentials) {
      throw new SecretProviderClientError({
        code: "access_denied",
        provider: INFISICAL_PROVIDER_ID,
        operation,
        message: "Infisical Universal-Auth credentials are not configured on the server.",
        rawMessage: "INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET missing from server environment",
      });
    }
    return { config, credentials, gateway: resolveGateway() };
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
    if (input?.providerConfig && vaultSiteUrlOverrideIgnored(input.providerConfig)) {
      warnings.push(
        "The vault siteUrl is ignored: the Infisical origin is pinned server-side to INFISICAL_SITE_URL (SEC-1). Remove the per-company siteUrl to clear this warning.",
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
    // ---- Managed writes are unsupported: Paperclip never writes into Infisical ----
    async createSecret(): Promise<PreparedSecretVersion> {
      return managedUnsupported("managed secret create");
    },
    async createVersion(): Promise<PreparedSecretVersion> {
      return managedUnsupported("managed secret version create");
    },
    // ---- Phase 1b live: reference link + runtime resolution ----
    async linkExternalSecret(input): Promise<PreparedSecretVersion> {
      const { config, credentials, gateway } = requireResolutionContext(
        "linkExternalSecret",
        input.providerConfig,
      );
      const ref = parseInfisicalRef(input.externalRef, config.secretPath);
      try {
        const session = await gateway.login({
          siteUrl: config.siteUrl as string,
          clientId: credentials.clientId,
          clientSecret: credentials.clientSecret,
        });
        // Validate the referenced secret exists at link time. We discard the
        // value — only the reference coordinates are persisted.
        await gateway.readSecret({
          siteUrl: config.siteUrl as string,
          accessToken: session.accessToken,
          projectId: config.projectId as string,
          environment: config.environment as string,
          secretPath: ref.secretPath,
          secretKey: ref.secretKey,
        });
      } catch (error) {
        normalizeInfisicalError("linkExternalSecret", error);
      }
      return buildExternalReferenceMaterial(config, ref);
    },
    async resolveVersion(input): Promise<string> {
      const { config, credentials, gateway } = requireResolutionContext(
        "resolveVersion",
        input.providerConfig,
      );
      // Prefer the stored material coordinates; fall back to the external ref.
      const stored = asInfisicalMaterial(input.material);
      const ref =
        stored.secretKey
          ? { secretPath: normalizeSecretPath(stored.secretPath), secretKey: stored.secretKey }
          : parseInfisicalRef(input.externalRef, config.secretPath);
      try {
        const session = await gateway.login({
          siteUrl: config.siteUrl as string,
          clientId: credentials.clientId,
          clientSecret: credentials.clientSecret,
        });
        return await gateway.readSecret({
          siteUrl: config.siteUrl as string,
          accessToken: session.accessToken,
          projectId: config.projectId as string,
          environment: config.environment as string,
          secretPath: ref.secretPath,
          secretKey: ref.secretKey,
        });
      } catch (error) {
        normalizeInfisicalError("resolveVersion", error);
      }
    },
    async deleteOrArchive(): Promise<void> {
      // External references are not owned by Paperclip; unlinking removes only
      // the Paperclip-side reference. Nothing is deleted or archived in Infisical.
      return;
    },
    healthCheck,
  };
}

export const infisicalProvider = createInfisicalProvider();
