import { createApp } from "vue";
import { createPinia } from "pinia";
import SettingsApp from "./SettingsApp.vue";

createApp(SettingsApp).use(createPinia()).mount("#app");
