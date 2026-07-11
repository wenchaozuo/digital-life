import {
  LifeIdentityManager,
  type LifeIdentity,
} from "./lifeIdentity";
import { initializeDefaultPersona } from "../persona";

export const lifeIdentityManager = new LifeIdentityManager();

export async function initializeDefaultLife(): Promise<LifeIdentity> {
  const currentLife = await lifeIdentityManager.getCurrent();
  if (currentLife) {
    return currentLife;
  }

  const persona = await initializeDefaultPersona();
  return lifeIdentityManager.create({
    name: "Digital Life",
    bodyId: "default-png",
    personaId: persona.id,
    personaVersion: persona.version,
  });
}
