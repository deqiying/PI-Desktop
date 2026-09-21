/**
 * Policy layer for the trusted-extension host-proxy methods (plan S1/D7).
 *
 * S1 only needs the read handler: `extensions.providers.list`. It answers with
 * the ready-model catalogue for the session the call came from, and only when
 * one of the plugins contributing extensions to that session holds
 * `models.list`.
 *
 * The subject is resolved from state main owns — the session→project map main
 * populated at launch plus the loaded-plugin registry — never from the wire,
 * which carries only `sessionId`. An id absent from that map is refused without
 * a catalogue read, so a module cannot name another session's id to borrow its
 * project grant, and an unknown id cannot degrade to "global plugins apply".
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
  /**
   * The project each live session owns, as main recorded it at launch. The wire
   * names a session id; only an id in this map has a known project.
   */
  sessionProjects: Map<string, string | null>;
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
  const { catalog, getHost, activeInProject, audit, plugins, sessionProjects } =
    options;

  /** One denial row, attributed to whatever identity the call could carry. */
  const deny = (
    sessionId: string,
    pluginIds: string[],
  ): { models: HostModelDescriptor[] } => {
    audit({
      api: AUDIT_API,
      ok: false,
      errorCode: "PERMISSION_DENIED",
      count: 0,
      sessionId,
      pluginIds,
      ts: Date.now(),
    });
    return { models: [] };
  };

  const listProviderModels = async (
    params: unknown,
  ): Promise<{ models: HostModelDescriptor[] }> => {
    const sessionId = sessionIdOf(params);
    const host = getHost();
    // `sessionId` is wire input. Without a live host, or without a session main
    // actually owns, there is no subject to check: the answer is a denial, not
    // an empty success, and no catalogue read happens.
    if (!host || !sessionId || !sessionProjects.has(sessionId)) {
      return deny(sessionId, []);
    }

    const projectPath = sessionProjects.get(sessionId) ?? null;
    const contributing = plugins
      .getAgentExtensions()
      .filter((extension) => activeInProject(extension.pluginId, projectPath));
    const pluginIds = [
      ...new Set(contributing.map((extension) => extension.pluginId)),
    ];
    if (
      !contributing.some((extension) =>
        plugins.pluginHasPermission(
          extension.pluginId,
          MODELS_LIST_PERMISSION,
        ),
      )
    ) {
      return deny(sessionId, pluginIds);
    }

    // A catalogue failure rejects the call instead of answering "no models":
    // an unreachable host and a host with no ready models must not look alike.
    // The rejected call is still audited, so a granted-then-failed call leaves
    // a trace.
    let models: HostModelDescriptor[];
    try {
      models = await catalog.listReadyModels();
    } catch (error) {
      audit({
        api: AUDIT_API,
        ok: false,
        errorCode: "UNSUPPORTED",
        count: 0,
        sessionId,
        pluginIds,
        ts: Date.now(),
      });
      throw error;
    }
    audit({
      api: AUDIT_API,
      ok: true,
      count: models.length,
      sessionId,
      pluginIds,
      ts: Date.now(),
    });
    return { models };
  };

  return { listProviderModels };
}
