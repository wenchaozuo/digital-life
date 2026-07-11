import { createApp } from "vue";
import { createPinia } from "pinia";
import SettingsApp from "./SettingsApp.vue";

try {
  createApp(SettingsApp).use(createPinia()).mount("#app");
  document.documentElement.dataset.page = "settings";
  if (import.meta.env.DEV) {
    console.info("[window:settings] mounted");
  }
} catch {
  document.documentElement.dataset.page = "error";
  document.querySelector("#app")?.replaceChildren("Page initialization failed.");
}
