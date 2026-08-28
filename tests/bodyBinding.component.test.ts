import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BODY_BINDING_CATALOG,
  DEFAULT_BODY_ID,
  createBodyPresentationForBinding,
  createBodyPresentationForBodyId,
  resolveBodyBinding,
} from "../src/body/index";

describe("body binding resolution", () => {
  it("resolves the registered default body without fallback", () => {
    expect(resolveBodyBinding(DEFAULT_BODY_ID)).toEqual({
      requestedBodyId: "default-png",
      effectiveBodyId: "default-png",
      usedFallback: false,
      presentationKind: "png",
    });
    expect(BODY_BINDING_CATALOG.size).toBe(1);
  });

  it("projects an unknown body to the default without changing the request", () => {
    expect(resolveBodyBinding("unregistered-body")).toEqual({
      requestedBodyId: "unregistered-body",
      effectiveBodyId: "default-png",
      usedFallback: true,
      presentationKind: "png",
    });
  });

  it("projects an empty body id to the default", () => {
    expect(resolveBodyBinding("")).toEqual({
      requestedBodyId: "",
      effectiveBodyId: "default-png",
      usedFallback: true,
      presentationKind: "png",
    });
  });

  it.each([
    "C:\\Users\\x\\model3.json",
    "../../model3.json",
    "https://example.invalid/model.json",
  ])("treats path-like selector %s as an opaque unknown id", (bodyId) => {
    const resolved = resolveBodyBinding(bodyId);

    expect(resolved.requestedBodyId).toBe(bodyId);
    expect(resolved.effectiveBodyId).toBe(DEFAULT_BODY_ID);
    expect(resolved.usedFallback).toBe(true);
    expect(resolved.presentationKind).toBe("png");
  });

  it.each(["DEFAULT-PNG", " default-png", "default-png/"])(
    "requires exact catalog matching for %s",
    (bodyId) => {
      const resolved = resolveBodyBinding(bodyId);

      expect(resolved.requestedBodyId).toBe(bodyId);
      expect(resolved.effectiveBodyId).toBe(DEFAULT_BODY_ID);
      expect(resolved.usedFallback).toBe(true);
    },
  );
});

describe("body binding presentation composition", () => {
  it("creates a fresh matched provider and renderer for every binding", async () => {
    const first = createBodyPresentationForBinding(
      resolveBodyBinding(DEFAULT_BODY_ID),
    );
    const second = createBodyPresentationForBinding(
      resolveBodyBinding(DEFAULT_BODY_ID),
    );

    expect(first.provider).not.toBe(second.provider);
    expect(first.renderer).not.toBe(second.renderer);

    await first.provider.load("thinking");
    expect(second.provider.getCurrent().state).toBe("idle");
  });

  it("executes the real default PNG provider and renderer as a matched pair", async () => {
    const composition = createBodyPresentationForBodyId(DEFAULT_BODY_ID);
    const snapshot = await composition.provider.load("thinking");
    const host = document.createElement("div");

    expect(snapshot.state).toBe("thinking");
    await composition.renderer.mount(host);
    await composition.renderer.render(snapshot);

    const image = host.querySelector("img");
    expect(image).not.toBeNull();
    expect(image?.getAttribute("src")).toBe(snapshot.resourcePath);
    expect(image?.getAttribute("alt")).toBe("Digital Life thinking body");

    await composition.renderer.dispose();
    expect(host.childElementCount).toBe(0);
  });

  it("executes the real PNG presentation for an unknown selector fallback", async () => {
    const resolved = resolveBodyBinding("restored-unknown-body");
    const composition = createBodyPresentationForBinding(resolved);
    const snapshot = await composition.provider.load("thinking");
    const host = document.createElement("div");

    expect(resolved.usedFallback).toBe(true);
    await composition.renderer.mount(host);
    await composition.renderer.render(snapshot);

    expect(host.querySelector("img")).not.toBeNull();
    expect(snapshot.state).toBe("thinking");
    await composition.renderer.dispose();
  });

  it("keeps binding resolution read-only and free of authority writes", () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), "src/body/bodyBinding.ts"),
      "utf8",
    );

    expect(source).not.toMatch(/storageService|LifeIdentityManager|\binvoke\b/);
    expect(source).not.toMatch(
      /update_life_identity_base_info|save_life_identity/,
    );
  });

  it("does not interpret body ids as dynamic paths or URLs", () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), "src/body/bodyBinding.ts"),
      "utf8",
    );

    expect(source).not.toMatch(/import\s*\(/);
    expect(source).not.toMatch(/\bfetch\s*\(/);
    expect(source).not.toMatch(/path\.join|new\s+URL|filesystem/i);
  });
});
