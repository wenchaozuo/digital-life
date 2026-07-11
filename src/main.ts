import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import SettingsApp from "./settings/SettingsApp.vue";

declare global {
  interface Window {
    __DIGITAL_LIFE_WINDOW_KIND__?: "settings";
  }
}

const rootComponent =
  window.__DIGITAL_LIFE_WINDOW_KIND__ === "settings" ? SettingsApp : App;

createApp(rootComponent).use(createPinia()).mount("#app");
