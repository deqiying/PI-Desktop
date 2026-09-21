/**
 * Policy layer for the trusted-extension host-proxy methods (plan S1/D7).
 *
 * S1 only needs the read handler: `extensions.providers.list`. It answers with
 * the ready-model catalogue for the session the call came from, and only when
 * one of the plugins contributing extensions to that session holds
 * `models.list`.
 *
 * The subject is resolved from state main owns — the session record plus the
 * loaded-plugin registry — never from the wire, which carries only `sessionId`.
 * Two plugins contributing to one session cannot be told apart at runtime
 * (their modules share one process), so the gate is the union of their grants;
 * that residual limit is recorded in the plan (D7).
 */

import type { HostModelDescriptor } from "@pi-desktop/agent-runtime";
import type { HostProcess } from "../host-process";
import type { ExtensionModelCatalog } from "./extension-model-catalog";

/** The permission a plugin must hold for its extensions to read the catalogue. */
const MODELS_LIST_PERMISSION = "models.list";

/** Audit operation name; matches the permission the call is gated by. */
const AUDIT_API = "models.list";

export type ExtensionProviderAccess = {
  listProviderModels(params: unknown): Promise<{ models: HostModelDescriptor[] }>;
};

export type ExtensionProviderAccessOptions = {
  catalog: ExtensionModelCatalog;
  getHost: () => Pick<HostProcess, "call"> | null;
  activeInProject: (pluginId: string, projectPath: string | null) => boolean;
  /** Same sink shape as the plugin host services' audit callback. */
  audit: (entry: Record<string, unknown>) => void;
  plugins: {
    getAgentExtensions(): Array<{ pluginId: string; id: string }>;
    pluginHasPermission(pluginId: string, permission: string): boolean;
  };
};

/** A session id is the only identity the wire carries; an empty one is refused. */
function sessionIdOf(params: unknown): string {
  if (!params || typeof params !== "object") return "";
  const value = (params as { sessionId?: unknown }).sessionId;
  return typeof value === "string" ? value.trim() : "";
}

export function createExtensionProviderAccess(
  options: ExtensionProviderAccessOptions,
): ExtensionProviderAccess {
  const { catalog, getHost, activeInProject, audit, plugins } = options;

  const listProviderModels = async (
    params: unknown,
  ): Promise<{ models: HostModelDescriptor[] }> => {
    const denied = (): { models: HostModelDescriptor[] } => {
      audit({
        api: AUDIT_API,
        ok: false,
        errorCode: "PERMISSION_DENIED",
        count: 0,
        ts: Date.now(),
      });
      return { models: [] };
    };
    const sessionId = sessionIdOf(params);
    const host = getHost();
    // Without a live host or a session to attribute the call to there is no
    // subject to check, so the answer is a denial rather than an empty success.
    if (!host || !sessionId) return denied();

    let projectPath: string | null = null;
    try {
      const result = await host.call<{
        session?: { projectPath?: string } | null;
      }>("session.get", { id: sessionId });
      projectPath = result?.session?.projectPath?.trim() || null;
    } catch {
      // An unresolvable session keeps the project filter at its strictest:
      // project-scoped plugins stay out, global ones are unaffected.
      projectPath = null;
    }
    const contributing = plugins
      .getAgentExtensions()
      .filter((extension) => activeInProject(extension.pluginId, projectPath));
    if (
      !contributing.some((extension) =>
        plugins.pluginHasPermission(
          extension.pluginId,
          MODELS_LIST_PERMISSION,
        ),
      )
    ) {
      return denied();
    }

    // A catalogue failure rejects the call instead of answering "no models":
    // an unreachable host and a host with no ready models must not look alike.
    const models = await catalog.listReadyModels();
    audit({ api: AUDIT_API, ok: true, count: models.length, ts: Date.now() });
    return { models };
  };

  return { listProviderModels };
}
