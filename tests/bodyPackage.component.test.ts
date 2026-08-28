import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BODY_STATES,
  DEFAULT_BODY_ID,
  createBodyPresentationForBodyId,
  resolveBodyBinding,
} from "../src/body";

describe("bundled body package foundation", () => {
  it("resolves the default package into a real PNG provider and renderer", async () => {
    const composition = createBodyPresentationForBodyId(DEFAULT_BODY_ID);
    const snapshot = await composition.provider.switchState("thinking");
    const host = document.createElement("div");

    await composition.renderer.mount(host);
    await composition.renderer.render(snapshot);

    const image = host.querySelector("img");
    expect(image).not.toBeNull();
    expect(image?.getAttribute("src")).toBe(snapshot.resourcePath);
    expect(image?.getAttribute("alt")).toBe("Digital Life thinking body");

    await composition.renderer.dispose();
    expect(host.childElementCount).toBe(0);
  });

  it("executes the real default package for all five body states", async () => {
    const provider = createBodyPresentationForBodyId(DEFAULT_BODY_ID).provider;
    const resourcePaths = new Set<string>();

    for (const state of BODY_STATES) {
      const snapshot = await provider.switchState(state);
      expect(snapshot.state).toBe(state);
      expect(snapshot.resourcePath.length).toBeGreaterThan(0);
      resourcePaths.add(snapshot.resourcePath);
    }

    // V1 has one truthful bundled PNG; distinct assets are not fabricated.
    expect(resourcePaths.size).toBe(1);
  });

  it("projects an unknown authoritative body to the real default package", async () => {
    const life = { bodyId: "future-unknown-body" };
    const resolved = resolveBodyBinding(life.bodyId);
    const composition = createBodyPresentationForBodyId(life.bodyId);
    const snapshot = await composition.provider.switchState("thinking");
    const host = document.createElement("div");

    await composition.renderer.mount(host);
    await composition.renderer.render(snapshot);

    expect(resolved).toEqual({
      requestedBodyId: "future-unknown-body",
      effectiveBodyId: DEFAULT_BODY_ID,
      usedFallback: true,
      presentationKind: "png",
    });
    expect(snapshot.state).toBe("thinking");
    expect(host.querySelector("img")).not.toBeNull();
    expect(life.bodyId).toBe("future-unknown-body");

    await composition.renderer.dispose();
  });

  it("keeps package runtime provider and renderer instances fresh", async () => {
    const first = createBodyPresentationForBodyId(DEFAULT_BODY_ID);
    const second = createBodyPresentationForBodyId(DEFAULT_BODY_ID);

    expect(first.provider).not.toBe(second.provider);
    expect(first.renderer).not.toBe(second.renderer);

    await first.provider.switchState("thinking");
    expect(second.provider.getCurrent().state).toBe("idle");
  });

  it("keeps package definitions and raw package composition helpers out of the public barrel", () => {
    const packageSource = fs.readFileSync(
      path.join(process.cwd(), "src/body/bodyPackage.ts"),
      "utf8",
    );
    const indexSource = fs.readFileSync(
      path.join(process.cwd(), "src/body/index.ts"),
      "utf8",
    );

    expect(packageSource).toMatch(/type BodyPackageDefinition/);
    expect(packageSource).toMatch(/interface PngBodyPackage/);
    expect(packageSource).toMatch(/interface Live2DBodyPackage/);
    expect(packageSource).toMatch(/BODY_PACKAGE_CATALOG/);
    expect(packageSource).not.toMatch(/export interface BodyPackageDefinition/);
    expect(indexSource).not.toMatch(/BODY_PACKAGE_CATALOG/);
    expect(indexSource).not.toMatch(/BodyPackageDefinition/);
    expect(indexSource).not.toMatch(/createPackagePresentation/);
    expect(indexSource).not.toMatch(/DEFAULT_BUNDLED_PNG_RESOURCES/);
  });

  it("keeps the resolved binding free of resources and asset locations", () => {
    const resolved = resolveBodyBinding("future-unknown-body");
    const keys = Object.keys(resolved);

    expect(keys).not.toContain("resourcePath");
    expect(keys).not.toContain("resources");
    expect(keys).not.toContain("assetPath");
    expect(keys).not.toContain("modelPath");
    expect(keys).not.toContain("texturePath");
    expect(keys).not.toContain("url");
  });

  it("keeps App opaque to package definitions and bundled asset paths", () => {
    const appSource = fs.readFileSync(
      path.join(process.cwd(), "src/App.vue"),
      "utf8",
    );

    expect(appSource).toContain("life.bodyId");
    expect(appSource).toContain("createBodyPresentationForBodyId");
    expect(appSource).not.toMatch(/BodyPackageDefinition|PngBodyResources/);
    expect(appSource).not.toContain("digital-life-idle.png");
    expect(appSource).not.toMatch(/assetPath|modelPath|texturePath/);
  });

  it("leaves the canonical bodyId factory as the only public composition entrypoint", () => {
    const indexSource = fs.readFileSync(
      path.join(process.cwd(), "src/body/index.ts"),
      "utf8",
    );

    expect(indexSource).toMatch(/createBodyPresentationForBodyId/);
    expect(indexSource).not.toMatch(/createBodyPresentationForPackage/);
    expect(indexSource).not.toMatch(/createBodyPresentationForResources/);
    expect(indexSource).not.toMatch(/registerBodyPackage|replaceBodyPackage|deleteBodyPackage/);
  });
});
