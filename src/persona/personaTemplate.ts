export type InitiativeLevel = "low" | "balanced" | "high";

export interface CommunicationStyle {
  /** General tone used in user-facing language. */
  tone: string;
  /** Forms of expression the persona should prefer. */
  preferredExpressions: string[];
  /** Forms of expression the persona should avoid. */
  avoidedExpressions: string[];
}

export interface PersonaTemplate {
  /** Stable identifier for this persona template. */
  id: string;
  /** User-editable template name. */
  name: string;
  /** Incremented whenever this template is updated. */
  version: number;
  /** Principles that guide future persona decisions. */
  coreValues: string[];
  /** Descriptive personality traits. */
  personalityTraits: string[];
  /** Expression preferences for future response construction. */
  communicationStyle: CommunicationStyle;
  /** Optional narrative or real-world background summary. */
  background: string;
  /** Topics and activities the persona is interested in. */
  interests: string[];
  /** Preferred degree of proactive behavior. */
  initiativeLevel: InitiativeLevel;
  /** Explicit interaction and behavior boundaries. */
  boundaries: string[];
}

export type CreatePersonaTemplateInput = Omit<PersonaTemplate, "id" | "version">;
export type UpdatePersonaTemplateInput = Partial<
  Omit<PersonaTemplate, "id" | "version">
>;

function cloneTemplate(template: PersonaTemplate): PersonaTemplate {
  return {
    ...template,
    coreValues: [...template.coreValues],
    personalityTraits: [...template.personalityTraits],
    communicationStyle: {
      ...template.communicationStyle,
      preferredExpressions: [...template.communicationStyle.preferredExpressions],
      avoidedExpressions: [...template.communicationStyle.avoidedExpressions],
    },
    interests: [...template.interests],
    boundaries: [...template.boundaries],
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isCommunicationStyle(value: unknown): value is CommunicationStyle {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.tone === "string" &&
    isStringArray(candidate.preferredExpressions) &&
    isStringArray(candidate.avoidedExpressions)
  );
}

function isInitiativeLevel(value: unknown): value is InitiativeLevel {
  return value === "low" || value === "balanced" || value === "high";
}

function isPersonaTemplate(value: unknown): value is PersonaTemplate {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.name === "string" &&
    typeof candidate.version === "number" &&
    Number.isInteger(candidate.version) &&
    candidate.version > 0 &&
    isStringArray(candidate.coreValues) &&
    isStringArray(candidate.personalityTraits) &&
    isCommunicationStyle(candidate.communicationStyle) &&
    typeof candidate.background === "string" &&
    isStringArray(candidate.interests) &&
    isInitiativeLevel(candidate.initiativeLevel) &&
    isStringArray(candidate.boundaries)
  );
}

import { storageService } from "../storage";

export class PersonaManager {
  private currentPersonaId: string | undefined;

  async create(input: CreatePersonaTemplateInput): Promise<PersonaTemplate> {
    const template: PersonaTemplate = {
      id: crypto.randomUUID(),
      version: 1,
      ...input,
    };

    await storageService.savePersona(template);
    this.currentPersonaId = template.id;
    return cloneTemplate(template);
  }

  async getCurrent(): Promise<PersonaTemplate | undefined> {
    if (!this.currentPersonaId) {
      return undefined;
    }

    return this.getById(this.currentPersonaId);
  }

  async getById(id: string): Promise<PersonaTemplate | undefined> {
    const storedPersona = await storageService.getPersona(id);
    if (storedPersona) {
      const parsed: unknown = JSON.parse(storedPersona.personaJson);
      if (!isPersonaTemplate(parsed)) {
        throw new Error("Invalid persona template payload from storage.");
      }

      this.currentPersonaId = parsed.id;
      return cloneTemplate(parsed);
    }

    return undefined;
  }

  async update(update: UpdatePersonaTemplateInput): Promise<PersonaTemplate> {
    const currentPersona = await this.getCurrent();
    if (!currentPersona) {
      throw new Error("Cannot update a persona before creating or restoring it.");
    }

    const nextPersona: PersonaTemplate = {
      ...currentPersona,
      name: update.name ?? currentPersona.name,
      coreValues: update.coreValues ?? currentPersona.coreValues,
      personalityTraits:
        update.personalityTraits ?? currentPersona.personalityTraits,
      communicationStyle:
        update.communicationStyle ?? currentPersona.communicationStyle,
      background: update.background ?? currentPersona.background,
      interests: update.interests ?? currentPersona.interests,
      initiativeLevel: update.initiativeLevel ?? currentPersona.initiativeLevel,
      boundaries: update.boundaries ?? currentPersona.boundaries,
      version: currentPersona.version + 1,
    };

    await storageService.savePersona(nextPersona);
    return cloneTemplate(nextPersona);
  }

  async serialize(): Promise<string> {
    const currentPersona = await this.getCurrent();
    if (!currentPersona) {
      throw new Error("Cannot serialize a persona before creating or restoring it.");
    }

    return JSON.stringify(currentPersona);
  }

  async restore(serialized: string): Promise<PersonaTemplate> {
    const parsed: unknown = JSON.parse(serialized);
    if (!isPersonaTemplate(parsed)) {
      throw new Error("Invalid persona template payload.");
    }

    await storageService.savePersona(parsed);
    this.currentPersonaId = parsed.id;
    return cloneTemplate(parsed);
  }
}
