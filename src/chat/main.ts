import { createApp } from "vue";
import { createPinia } from "pinia";
import ChatView from "./ChatView.vue";

createApp(ChatView).use(createPinia()).mount("#app");
