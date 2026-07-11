import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import ChatView from "./chat/ChatView.vue";
import SettingsApp from "./settings/SettingsApp.vue";

declare global {
  interface Window {
    __DIGITAL_LIFE_WINDOW_KIND__?: "settings" | "chat";
  }
}

const rootComponent =
  window.__DIGITAL_LIFE_WINDOW_KIND__ === "settings"
    ? SettingsApp
    : window.__DIGITAL_LIFE_WINDOW_KIND__ === "chat"
      ? ChatView
      : App;

createApp(rootComponent).use(createPinia()).mount("#app");
