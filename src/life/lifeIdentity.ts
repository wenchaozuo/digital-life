export interface LifeIdentity {
  /** Stable identifier for this individual digital life. */
  id: string;
  /** User-visible display name. */
  name: string;
  /** ISO 8601 timestamp for the identity's first creation. */
  createdAt: string;
  /** Version of this identity record. */
  version: number;
  /** Identifier of the body resource binding. */
  bodyId: string;
  /** Identifier of the associated persona template. */
  personaId: string;
  /** Version reference for a future persona record. */
  personaVersion: number;
}

export interface CreateLifeIdentityInput {
  name: string;
  bodyId: string;
  personaId: string;
  personaVersion?: number;
}

export interface UpdateLifeIdentityInput {
  name?: string;
  bodyId?: string;
}

function cloneIdentity(identity: LifeIdentity): LifeIdentity {
  return { ...identity };
}

function isLifeIdentity(value: unknown): value is LifeIdentity {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.name === "string" &&
    typeof candidate.createdAt === "string" &&
    !Number.isNaN(Date.parse(candidate.createdAt)) &&
    typeof candidate.version === "number" &&
    Number.isInteger(candidate.version) &&
    candidate.version > 0 &&
    typeof candidate.bodyId === "string" &&
    typeof candidate.personaId === "string" &&
    typeof candidate.personaVersion === "number" &&
    Number.isInteger(candidate.personaVersion) &&
    candidate.personaVersion > 0
  );
}

import { storageService } from "../storage";

export class LifeIdentityManager {
  async create(input: CreateLifeIdentityInput): Promise<LifeIdentity> {
    const identity: LifeIdentity = {
      id: crypto.randomUUID(),
      name: input.name,
      createdAt: new Date().toISOString(),
      version: 1,
      bodyId: input.bodyId,
      personaId: input.personaId,
      personaVersion: input.personaVersion ?? 1,
    };

    await storageService.saveLife(identity);
    return cloneIdentity(identity);
  }

  async getCurrent(): Promise<LifeIdentity | undefined> {
    const identity = await storageService.getCurrentLife();
    return identity && cloneIdentity(identity);
  }

  async updateBaseInfo(update: UpdateLifeIdentityInput): Promise<LifeIdentity> {
    const currentLife = await this.getCurrent();
    if (!currentLife) {
      throw new Error("Cannot update a life before creating or restoring it.");
    }

    const identity = await storageService.updateLifeBaseInfo(
      currentLife.id,
      update.name ?? currentLife.name,
      update.bodyId ?? currentLife.bodyId,
    );
    return cloneIdentity(identity);
  }

  async serialize(): Promise<string> {
    const currentLife = await this.getCurrent();
    if (!currentLife) {
      throw new Error("Cannot serialize a life before creating or restoring it.");
    }

    return JSON.stringify(currentLife);
  }

  async restore(serialized: string): Promise<LifeIdentity> {
    const parsed: unknown = JSON.parse(serialized);
    if (!isLifeIdentity(parsed)) {
      throw new Error("Invalid life identity payload.");
    }

    await storageService.saveLife(parsed);
    return cloneIdentity(parsed);
  }
}
