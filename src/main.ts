import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";

function showMountFailure(): void {
  document.documentElement.dataset.page = "error";
  document.querySelector("#app")?.replaceChildren("Page initialization failed.");
}

try {
  createApp(App).use(createPinia()).mount("#app");
  document.documentElement.dataset.page = "main";
  if (import.meta.env.DEV) {
    console.info("[window:main] mounted");
  }
} catch {
  showMountFailure();
}
