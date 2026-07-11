import { PersonaManager, type PersonaTemplate } from "./personaTemplate";

export const personaManager = new PersonaManager();

export async function initializeDefaultPersona(): Promise<PersonaTemplate> {
  const currentPersona = await personaManager.getCurrent();
  if (currentPersona) {
    return currentPersona;
  }

  return personaManager.create({
    name: "Custom Persona",
    coreValues: [],
    personalityTraits: [],
    communicationStyle: {
      tone: "",
      preferredExpressions: [],
      avoidedExpressions: [],
    },
    background: "",
    interests: [],
    initiativeLevel: "balanced",
    boundaries: [],
  });
}
