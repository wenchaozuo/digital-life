import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodySnapshot } from "./types.ts";

// D18-B1 PNG renderer implementation of the renderer-neutral contract.
//
// It owns exactly one image element inside its supplied host, preserves the
// snapshot state as the accessible image label, and disposes only its own
// renderer subtree via `host.replaceChildren()`.  No global document query,
// no element-ID singleton, no global document append.

export class PngBodyRenderer {
  private host: HTMLElement | undefined;
  private image: HTMLImageElement | undefined;

  mount(host: HTMLElement): void {
    if (this.host === host) {
      return;
    }
    const image = document.createElement("img");
    image.draggable = false;
    host.replaceChildren(image);
    this.host = host;
    this.image = image;
  }

  render(snapshot: BodySnapshot): void {
    const image = this.image;
    if (image === undefined) {
      throw new BodyRendererError("PNG renderer is not mounted.");
    }
    image.setAttribute("src", snapshot.resourcePath);
    // Accessibility: the snapshot state is preserved as the visible label.
    image.setAttribute("alt", `Digital Life ${snapshot.state} body`);
  }

  dispose(): void {
    const host = this.host;
    if (host !== undefined) {
      host.replaceChildren();
    }
    this.host = undefined;
    this.image = undefined;
  }
}