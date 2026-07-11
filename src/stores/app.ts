import { defineStore } from "pinia";

export const useAppStore = defineStore("app", {
  state: () => ({
    appReady: true,
    currentVersion: "V0.1" as const,
  }),
});
