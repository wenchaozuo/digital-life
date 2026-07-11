import { createApp } from "vue";
import { createPinia } from "pinia";
import ChatView from "./ChatView.vue";

try {
  createApp(ChatView).use(createPinia()).mount("#app");
  document.documentElement.dataset.page = "chat";
  if (import.meta.env.DEV) {
    console.info("[window:chat] mounted");
  }
} catch {
  document.documentElement.dataset.page = "error";
  document.querySelector("#app")?.replaceChildren("Page initialization failed.");
}
