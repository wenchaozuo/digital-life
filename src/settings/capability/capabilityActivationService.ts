import { invoke } from "@tauri-apps/api/core";

/**
 * D30-A capability activation service.
 *
 * This module is a thin, display-only control surface over the durable D28
 * authorization root. It sends exactly three caller-controlled values on a
 * transition — the capability id, the desired state, and the revision last
 * observed — and it never sends a life id, event id, provenance, scope, risk,
 * approval floor, grant, or revision to mint. The Host derives all of those.
 */

export type CapabilityRiskClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type CapabilityApprovalFloor =
  | "ROOT_ENABLED"
  | "EXPLICIT_PER_ACTION"
  | "FORBIDDEN";

export type CapabilityScopeRequirement =
  | "NONE"
  | "WORKSPACE_REQUIRED"
  | "NETWORK_DESTINATION_REQUIRED"
  | "EXTERNAL_RESOURCE_REQUIRED";

export interface CapabilityDescriptorView {
  capabilityId: string;
  displayName: string;
  riskClass: CapabilityRiskClass;
  approvalFloor: CapabilityApprovalFloor;
  scopeRequirement: CapabilityScopeRequirement;
  readOnly: boolean;
}

export interface CapabilityAuthorizationEventView {
  oldEnabled: boolean;
  newEnabled: boolean;
  oldRevision: number;
  newRevision: number;
  changedAt: string;
  actorKind: string;
  provenanceKind: string;
}

export interface CapabilityAuthorizationEntryView extends CapabilityDescriptorView {
  enabled: boolean;
  revision: number;
  createdAt: string;
  updatedAt: string;
  recentAuthorizationEvents: CapabilityAuthorizationEventView[];
}

export interface CapabilityAuthorizationSnapshot {
  lifeId: string;
  capabilities: CapabilityAuthorizationEntryView[];
}

export interface CapabilityAuthorizationUpdateResult {
  capabilityId: string;
  enabled: boolean;
  revision: number;
  previousEnabled: boolean;
  previousRevision: number;
  transition: "applied" | "replayed";
  events: CapabilityAuthorizationEventView[];
}

/** Stable failure codes emitted by the Host control plane. */
export const CAPABILITY_ACTIVATION_CODES = {
  settingsWindowRequired: "CAPABILITY_ACTIVATION_SETTINGS_WINDOW_REQUIRED",
  lifeNotAvailable: "LIFE_NOT_AVAILABLE",
  unknownCapability: "CAPABILITY_ACTIVATION_UNKNOWN_CAPABILITY",
  revisionConflict: "CAPABILITY_ACTIVATION_REVISION_CONFLICT",
  noTransition: "CAPABILITY_ACTIVATION_NO_TRANSITION",
  notProvisioned: "CAPABILITY_ACTIVATION_NOT_PROVISIONED",
  invalidRequest: "CAPABILITY_ACTIVATION_INVALID_REQUEST",
  storageUnavailable: "CAPABILITY_ACTIVATION_STORAGE_UNAVAILABLE",
} as const;

export const capabilityActivationService = {
  async getSnapshot(): Promise<CapabilityAuthorizationSnapshot> {
    return invoke<CapabilityAuthorizationSnapshot>(
      "get_capability_authorization_snapshot",
    );
  },

  async setEnabled(
    capabilityId: string,
    enabled: boolean,
    expectedRevision: number,
  ): Promise<CapabilityAuthorizationUpdateResult> {
    return invoke<CapabilityAuthorizationUpdateResult>(
      "set_capability_authorization_enabled",
      { capabilityId, enabled, expectedRevision },
    );
  },
};

/**
 * Extracts the Host failure code from a rejected IPC call. A Tauri command
 * that returns a structured error rejects with the serialized object, but a
 * transport-level failure can reject with an Error or string instead.
 */
export function activationErrorCode(caught: unknown): string | undefined {
  if (caught !== null && typeof caught === "object" && "code" in caught) {
    const code = (caught as { code?: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

/** Bounded, human-readable failure text. Never surfaces internal evidence. */
export function activationErrorText(caught: unknown, fallback: string): string {
  if (caught !== null && typeof caught === "object" && "message" in caught) {
    const message = (caught as { message?: unknown }).message;
    if (typeof message === "string" && message.length > 0) {
      return message.slice(0, 256);
    }
  }
  const value =
    typeof caught === "string" ? caught : caught instanceof Error ? caught.message : "";
  return (value || fallback).slice(0, 256);
}

/** Stable, user-facing description for a trusted capability. */
export function capabilityDescription(capabilityId: string): string {
  if (capabilityId === "vita.process.workspace.git_status") {
    return "Allows Vita Agent to request governed, read-only Git status for the active workspace. Every action still requires explicit confirmation.";
  }
  return "Allows Vita Agent to request this governed capability. Every action still requires explicit confirmation.";
}

/** True when the capability needs the strongest enable warning. */
export function requiresCriticalAcknowledgement(
  entry: Pick<CapabilityDescriptorView, "riskClass" | "approvalFloor">,
): boolean {
  return entry.riskClass === "CRITICAL";
}
