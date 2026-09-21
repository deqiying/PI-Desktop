/**
 * Transport for the trusted-extension provider request surface (plan S2,
 * decisions D3–D8).
 *
 * One call, one destination: the provider row the caller named supplies the
 * origin (D4) and the credential (D5); the caller supplies the path and the
 * envelope; main supplies the transport policy — no redirects, no automatic
 * retry, a bounded budget, bounded bodies, an abort registry, and one audit row.
 *
 * The gate that decides *whether* a call may happen lives in
 * `extension-provider-access.ts`; this module is handed a subject that has
 * already been authorized, and never reads the wire for identity.
 */

import { createContainedFileReader } from "../services/contained-file-reader";
import type { HostProcess } from "../host-process";
import { modelIdsMatch, type ProviderPublic } from "@pi-desktop/shared";
import {
  mergeProviderHeaders,
  type ExtensionProviderRequestResult,
} from "@pi-desktop/agent-runtime";
import {
  MULTIPART_FILE_MAX_BYTES,
  MULTIPART_TOTAL_MAX_BYTES,
  assembleRequestBody,
  callerHeaders,
  isRequestMethod,
  requestError,
  requestErrorCode,
  requestMethod,
  requestTimeoutMs,
  resolveRequestUrl,
} from "./extension-request-envelope";
import {
  providerRequestAudit,
  responseResult,
} from "./extension-request-response";

/** Who the call is for, as main decided it (plan D7). */
export type ProviderRequestSubject = {
  sessionId: string;
  /** The project this session owns, as main recorded it at launch. */
  projectPath?: string;
  /** The contributing plugins whose grants the gate accepted, for the audit row. */
  pluginIds: string[];
  /** The claimed extension id; attribution only. */
  extensionId: string;
  callId: string;
};

export type ExtensionProviderRequestHandler = {
  perform(
    params: Record<string, unknown>,
    subject: ProviderRequestSubject,
  ): Promise<ExtensionProviderRequestResult>;
  /** `extensions.providers.abort`: cancel one in-flight call by its id. */
  abort(params: unknown): { ok: boolean };
  /** Runtime disposal: nothing this handler started may outlive it (D8). */
  abortAll(): void;
};

export type ExtensionProviderRequestOptions = {
  getHost: () => Pick<HostProcess, "call"> | null;
  dataDir: string;
  fetchImpl?: typeof fetch;
  audit: (entry: Record<string, unknown>) => void;
};

type CredentialHeader = { name: string; value: string };

/** The `apiStyle` → credential-header mapping the runtime's adapters use. */
function credentialHeaderFor(
  apiStyle: string | undefined,
  secret: string,
): CredentialHeader {
  if (apiStyle === "anthropic_messages") {
    return { name: "x-api-key", value: secret };
  }
  if (apiStyle === "google_generative_ai") {
    return { name: "x-goog-api-key", value: secret };
  }
  return { name: "authorization", value: `Bearer ${secret}` };
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function abortKey(sessionId: string, callId: string): string {
  return `${sessionId}\u0000${callId}`;
}

/**
 * The transport failure, reduced to a code. The message deliberately carries no
 * URL and no header value: a caller's query string and the provider's address
 * are not the host's to write into a log line, and a resolver error code is
 * enough to diagnose a failure.
 */
function transportError(
  error: unknown,
  state: { timedOut: boolean; aborted: boolean },
): Error {
  if (state.timedOut) {
    return requestError("TIMEOUT", "The provider request exceeded its budget");
  }
  if (state.aborted) {
    return requestError("ABORTED", "The provider request was aborted");
  }
  // A host code already decided (an oversized response, a rejected upload) is
  // not a transport failure and keeps the code the caller needs.
  if (typeof (error as { errorCode?: unknown } | null)?.errorCode === "string") {
    return error as Error;
  }
  const code = (error as { cause?: { code?: unknown } } | null)?.cause?.code;
  return requestError(
    "NETWORK_ERROR",
    typeof code === "string" && /^[A-Z0-9_]{1,32}$/.test(code)
      ? `The provider request failed (${code})`
      : "The provider request failed",
  );
}

export function createExtensionProviderRequest(
  options: ExtensionProviderRequestOptions,
): ExtensionProviderRequestHandler {
  const inFlight = new Map<string, AbortController>();
  const fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));

  /** The provider row and the credential, or the code that refuses the call (D5). */
  const resolveProvider = async (
    host: Pick<HostProcess, "call">,
    providerId: string,
    modelId: string,
  ): Promise<{ provider: ProviderPublic; credential?: CredentialHeader }> => {
    const { provider } = await host.call<{ provider?: ProviderPublic }>(
      "providers.get",
      { id: providerId },
    );
    if (!provider || provider.enabled === false || !provider.baseUrl) {
      throw requestError(
        "PROVIDER_NOT_FOUND",
        `provider "${providerId}" is not available`,
      );
    }
    if (
      modelId &&
      !provider.models?.some((binding) => modelIdsMatch(binding.id, modelId))
    ) {
      throw requestError(
        "MODEL_NOT_CONFIGURED",
        `model "${modelId}" is not configured on provider "${provider.id}"`,
      );
    }
    // v1 excludes vendor accounts: their wire endpoint is model-dependent, so
    // `baseUrl` alone does not identify the destination (D5).
    if (provider.authKind === "oauth") {
      throw requestError(
        "PROVIDER_AUTH_UNSUPPORTED",
        "Vendor-account (OAuth) providers are not supported by this API",
      );
    }
    if (provider.authKind === "none") return { provider };
    const { value } = await host.call<{ value?: string }>("providers.getSecret", {
      id: provider.id,
    });
    if (!value) {
      throw requestError(
        "PROVIDER_AUTH_MISSING",
        `provider "${provider.id}" has no stored credential`,
      );
    }
    return {
      provider,
      credential: credentialHeaderFor(provider.apiStyle, value),
    };
  };

  /**
   * Uploaded files resolve against roots the host captured — the session's
   * project, the session's scratch directory, and the attachment store — never
   * against a path the caller supplied (D3). The reader is the shipped
   * containment rule with this surface's caps.
   */
  const fileReaderFor = (
    host: Pick<HostProcess, "call">,
    subject: ProviderRequestSubject,
  ): ((refs: string[]) => Promise<Uint8Array[]>) => {
    let reader: ((refs: string[]) => Promise<Uint8Array[]>) | undefined;
    return async (refs: string[]) => {
      if (refs.length === 0) return [];
      if (!reader) {
        const scratch = await host
          .call<{ path?: string }>("session.getScratchPath", {
            sessionId: subject.sessionId,
          })
          .catch(() => undefined);
        reader = createContainedFileReader({
          roots: {
            ...(subject.projectPath ? { projectPath: subject.projectPath } : {}),
            scratchPath: scratch?.path ?? options.dataDir,
            dataDir: options.dataDir,
          },
          maxFileBytes: MULTIPART_FILE_MAX_BYTES,
          maxSetBytes: MULTIPART_TOTAL_MAX_BYTES,
          maxBudgetBytes: MULTIPART_TOTAL_MAX_BYTES,
          codes: {
            outside: "FILE_OUTSIDE_ALLOWED_ROOTS",
            notFound: "FILE_NOT_FOUND",
            // "does not exist" and "is not a regular file" share the code the
            // documented error table gives them.
            invalid: "FILE_NOT_FOUND",
            fileTooLarge: "FILE_TOO_LARGE",
            setTooLarge: "UPLOAD_TOO_LARGE",
          },
        });
      }
      return await reader(refs);
    };
  };

  const perform = async (
    params: Record<string, unknown>,
    subject: ProviderRequestSubject,
  ): Promise<ExtensionProviderRequestResult> => {
    const startedAt = Date.now();
    const audit = (entry: Parameters<typeof providerRequestAudit>[0]): void => {
      options.audit(providerRequestAudit(entry));
    };
    // Every call leaves exactly one row, including a call refused before any
    // I/O — a mistake must be as visible as a failure.
    const fail = (error: unknown): never => {
      const errorCode =
        typeof (error as { errorCode?: unknown })?.errorCode === "string"
          ? (error as { errorCode: string }).errorCode
          : "UNSUPPORTED";
      audit({
        ok: false,
        sessionId: subject.sessionId,
        pluginIds: subject.pluginIds,
        ts: Date.now(),
        errorCode,
        // The method may be the very thing that was invalid, so it is reported
        // only when it is one the surface accepts.
        ...(isRequestMethod(asString(params.method))
          ? { method: asString(params.method) }
          : {}),
        durationMs: Date.now() - startedAt,
      });
      throw error;
    };

    try {
      // Cheap, purely local validation first: a caller's mistake costs no I/O.
      const host = options.getHost();
      if (!host) throw requestError("UNSUPPORTED", "The host is unavailable");
      const providerId = asString(params.providerId);
      if (!providerId) {
        throw requestError("INVALID_ARGUMENT", "providerId is required");
      }
      const modelId = asString(params.modelId);
      const method = requestMethod(params.method);
      const timeoutMs = requestTimeoutMs(params.timeoutMs);
      const headers = callerHeaders(params.headers);
      const { provider, credential } = await resolveProvider(
        host,
        providerId,
        modelId,
      );
      const url = resolveRequestUrl(provider.baseUrl, params.path);
      const body = await assembleRequestBody({
        body: params.body,
        method,
        readFiles: fileReaderFor(host, subject),
      });

      // Provider-configured headers first, then the caller's under the shared
      // provider-header caps, then the credential last so it always wins (D5).
      const composed = mergeProviderHeaders(provider.headers, headers) ?? {};
      const finalHeaders = new Headers(composed);
      if (credential) finalHeaders.set(credential.name, credential.value);
      if (body.contentType) finalHeaders.set("content-type", body.contentType);

      const controller = new AbortController();
      const key = abortKey(subject.sessionId, subject.callId);
      inFlight.set(key, controller);
      // One mutable record, so the timer and the failure mapping read the same
      // fact: a budget that expired is `TIMEOUT`, anything else that stopped the
      // fetch early is `ABORTED`.
      const transport = { timedOut: false };
      const timer = setTimeout(() => {
        transport.timedOut = true;
        controller.abort();
      }, timeoutMs);
      try {
        let response: Response;
        try {
          response = await fetchImpl(url, {
            method,
            headers: finalHeaders,
            // A redirect is never followed: the credential must not be re-sent
            // to a host the provider row did not name (D6).
            redirect: "manual",
            signal: controller.signal,
            ...(body.body !== undefined ? { body: body.body } : {}),
          });
        } catch (error) {
          throw transportError(error, {
            timedOut: transport.timedOut,
            aborted: !transport.timedOut && controller.signal.aborted,
          });
        }
        let result: ExtensionProviderRequestResult;
        try {
          result = await responseResult({
            response,
            ...(credential ? { credentialsHeader: credential.name } : {}),
            startedAt,
          });
        } catch (error) {
          throw transportError(error, {
            timedOut: transport.timedOut,
            aborted: !transport.timedOut && controller.signal.aborted,
          });
        }
        audit({
          ok: true,
          sessionId: subject.sessionId,
          pluginIds: subject.pluginIds,
          ts: Date.now(),
          status: result.status,
          method,
          durationMs: result.durationMs,
          // Counts and byte sizes only: never a path, a field value, or a header.
          ...(body.files !== undefined ? { files: body.files } : {}),
          bytes: body.bytes,
        });
        return result;
      } finally {
        clearTimeout(timer);
        inFlight.delete(key);
      }
    } catch (error) {
      return fail(error);
    }
  };

  return {
    perform,
    abort(params) {
      const sessionId = asString((params as { sessionId?: unknown })?.sessionId);
      const callId = asString((params as { callId?: unknown })?.callId);
      if (!sessionId || !callId) return { ok: false };
      const controller = inFlight.get(abortKey(sessionId, callId));
      if (!controller) return { ok: false };
      controller.abort();
      return { ok: true };
    },
    abortAll() {
      for (const controller of inFlight.values()) controller.abort();
      inFlight.clear();
    },
  };
}
