import { Application } from "pixi.js";

import {
  Live2DRenderer,
  createLive2DCoreReadyBoundary,
} from "../../src/body/live2dRenderer.ts";
import type { Live2DCoreReadyBoundary } from "../../src/body/live2dRenderer.ts";
import type { BodySnapshot, BodyState } from "../../src/body/types.ts";

const COMMIT = "b1de66b0b1f1cb881d95fb6158622aeb6a2827bd";
const CORE_URL =
  "https://cubism.live2d.com/sdk-web/cubismcore/live2dcubismcore.min.js";
const MODELS = {
  haru: `https://raw.githubusercontent.com/Live2D/CubismWebSamples/${COMMIT}/Samples/Resources/Haru/Haru.model3.json`,
  mark: `https://raw.githubusercontent.com/Live2D/CubismWebSamples/${COMMIT}/Samples/Resources/Mark/Mark.model3.json`,
  rice: `https://raw.githubusercontent.com/Live2D/CubismWebSamples/${COMMIT}/Samples/Resources/Rice/Rice.model3.json`,
} as const;

type SmokeModel = keyof typeof MODELS;
type WindowWithCubismCore = Window & { Live2DCubismCore?: unknown };

const host = document.querySelector<HTMLElement>("#live2d-host");
const status = document.querySelector<HTMLElement>("#smoke-status");
const dependencyStatus = document.querySelector<HTMLElement>("#dependency-status");
const modelSelect = document.querySelector<HTMLSelectElement>("#model-select");
const mountButton = document.querySelector<HTMLButtonElement>("#mount-button");
const resizeButton = document.querySelector<HTMLButtonElement>("#resize-button");
const disposeButton = document.querySelector<HTMLButtonElement>("#dispose-button");
const layoutStatus = document.querySelector<HTMLElement>("#layout-status");

function requireElement<T extends Element>(element: T | null): T {
  if (element === null) {
    throw new Error("D21 smoke harness markup is incomplete.");
  }
  return element;
}

const smokeHost = requireElement(host);
const smokeStatus = requireElement(status);
const smokeDependencyStatus = requireElement(dependencyStatus);
const smokeModelSelect = requireElement(modelSelect);
const smokeMountButton = requireElement(mountButton);
const smokeResizeButton = requireElement(resizeButton);
const smokeDisposeButton = requireElement(disposeButton);
const smokeLayoutStatus = requireElement(layoutStatus);

const pixiDependencyName = Application.name;

let renderer: Live2DRenderer | undefined;
let cubism4Ready = false;
let coreReadyBoundary: Live2DCoreReadyBoundary | undefined;
let compactHost = false;

function hasCubismCore(): boolean {
  return (
    (window as WindowWithCubismCore).Live2DCubismCore !== undefined
  );
}

async function loadCubism4(): Promise<string> {
  if (!hasCubismCore()) {
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = CORE_URL;
      script.async = true;
      script.onload = () => resolve();
      script.onerror = () =>
        reject(new Error("D21_B1_R1_CORE_NETWORK_SMOKE_UNAVAILABLE"));
      document.head.append(script);
    });
  }

  if (!hasCubismCore()) {
    throw new Error("D21_B1_R1_CORE_NETWORK_SMOKE_UNAVAILABLE");
  }
  const cubism4 = await import(
    "@jannchie/pixi-live2d-display/cubism4"
  );
  return cubism4.Live2DModel.name;
}

function selectedModel(): SmokeModel {
  const value = smokeModelSelect.value;
  if (value === "mark" || value === "rice") {
    return value;
  }
  return "haru";
}

function smokeSnapshot(state: BodyState): BodySnapshot {
  return {
    resourcePath: "/d21-smoke-controlled-fallback.png",
    state,
  };
}

async function mountSelectedModel(): Promise<void> {
  if (!cubism4Ready) {
    smokeStatus.textContent = "waiting for Cubism Core";
    return;
  }
  await renderer?.dispose();
  const model = selectedModel();
  const coreReady = coreReadyBoundary;
  if (coreReady === undefined) {
    smokeStatus.textContent = "D21_B2_CORE_NOT_READY";
    return;
  }
  const nextRenderer = new Live2DRenderer({
    modelUrl: MODELS[model],
    coreReady,
  });
  renderer = nextRenderer;
  smokeStatus.textContent = `mounting ${model}`;
  try {
    await nextRenderer.mount(smokeHost);
    await nextRenderer.render(smokeSnapshot("idle"));
    smokeStatus.textContent = `mounted ${model}; canvas=${smokeHost.querySelectorAll("canvas").length}`;
    const canvas = smokeHost.querySelector<HTMLCanvasElement>("canvas");
    smokeLayoutStatus.textContent = canvas
      ? `layout ${canvas.dataset.live2dWidth}x${canvas.dataset.live2dHeight}; scale=${canvas.dataset.live2dModelScale}`
      : "layout unavailable";
  } catch (error) {
    await nextRenderer.dispose();
    if (renderer === nextRenderer) {
      renderer = undefined;
    }
    smokeStatus.textContent = `failed ${model}: ${error instanceof Error ? error.message : "unknown error"}`;
  }
}

async function resizeSelectedModel(): Promise<void> {
  const current = renderer;
  if (current === undefined) {
    smokeLayoutStatus.textContent = "layout unavailable: renderer is unmounted";
    return;
  }

  compactHost = !compactHost;
  smokeHost.style.width = compactHost ? "320px" : "";
  smokeHost.style.height = compactHost ? "480px" : "";
  await new Promise<void>((resolve) => window.setTimeout(resolve, 0));

  try {
    await current.resize();
    const canvas = smokeHost.querySelector<HTMLCanvasElement>("canvas");
    smokeLayoutStatus.textContent = canvas
      ? `resized ${canvas.dataset.live2dWidth}x${canvas.dataset.live2dHeight}; scale=${canvas.dataset.live2dModelScale}`
      : "resize completed without canvas";
  } catch (error) {
    smokeLayoutStatus.textContent = `resize failed: ${error instanceof Error ? error.message : "unknown error"}`;
  }
}

async function disposeSelectedModel(): Promise<void> {
  const current = renderer;
  renderer = undefined;
  await current?.dispose();
  smokeStatus.textContent = `disposed; canvas=${smokeHost.querySelectorAll("canvas").length}`;
  smokeLayoutStatus.textContent = "layout disposed";
}

smokeMountButton.addEventListener("click", () => {
  void mountSelectedModel();
});
smokeResizeButton.addEventListener("click", () => {
  void resizeSelectedModel();
});
smokeDisposeButton.addEventListener("click", () => {
  void disposeSelectedModel();
});
smokeModelSelect.addEventListener("change", () => {
  void mountSelectedModel();
});

const initial = new URLSearchParams(window.location.search).get("model");
if (initial === "mark" || initial === "rice" || initial === "haru") {
  smokeModelSelect.value = initial;
}

async function initializeSmoke(): Promise<void> {
  try {
    const cubism4DependencyName = await loadCubism4();
    cubism4Ready = true;
    coreReadyBoundary = createLive2DCoreReadyBoundary();
    smokeDependencyStatus.textContent = `${pixiDependencyName} + ${cubism4DependencyName} loaded; Core is test-page supplied.`;
    await mountSelectedModel();
  } catch (error) {
    smokeDependencyStatus.textContent = `Core unavailable: ${error instanceof Error ? error.message : "unknown error"}`;
    smokeStatus.textContent = "D21_B1_R1_CORE_NETWORK_SMOKE_UNAVAILABLE";
  }
}

void initializeSmoke();
