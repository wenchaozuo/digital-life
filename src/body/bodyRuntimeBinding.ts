import { BodyRenderCoordinator } from "./bodyRenderCoordinator.ts";
import { BodyRendererHost } from "./bodyRenderer.ts";
import type { BodyPresentationComposition } from "./bodyBinding.ts";
import type { InstalledBodyPackageSnapshot } from "./bodyPackageService.ts";
import type { LifeIdentity } from "../life";
import type { BodySnapshot, BodyState } from "./types.ts";

export interface BodyRuntimeBindingAuthority {
  loadRegistrySnapshot(): Promise<readonly InstalledBodyPackageSnapshot[]>;
  installRegistrySnapshot(
    snapshots: readonly InstalledBodyPackageSnapshot[],
  ): void;
  loadCurrentLife(): Promise<LifeIdentity | undefined>;
}

export interface BodyRuntimeBindingControllerOptions
  extends BodyRuntimeBindingAuthority {
  createPresentation(bodyId: string): BodyPresentationComposition;
  getCurrentState(): BodyState;
  onSnapshot?(snapshot: BodySnapshot): void;
}

interface ActiveBinding {
  readonly generation: number;
  readonly bodyId: string;
  readonly coordinator: BodyRenderCoordinator;
  readonly host: BodyRendererHost;
}

/**
 * Main-WebView owner for the one active body coordinator and renderer host.
 * Authority reads happen before every rebind; package definitions, URLs, and
 * renderer instances never cross into Settings or Chat.
 */
export class BodyRuntimeBindingController {
  private readonly options: BodyRuntimeBindingControllerOptions;
  private hostElement: HTMLElement | undefined;
  private activeBinding: ActiveBinding | undefined;
  private pendingBinding: ActiveBinding | undefined;
  private bindingGeneration = 0;
  private refreshGeneration = 0;
  private retirementTail: Promise<void> = Promise.resolve();
  private disposed = false;

  constructor(options: BodyRuntimeBindingControllerOptions) {
    this.options = options;
  }

  get currentBodyId(): string | undefined {
    return this.activeBinding?.bodyId;
  }

  attachHost(hostElement: HTMLElement | undefined): void {
    this.hostElement = hostElement;
  }

  async initialize(
    hostElement: HTMLElement | undefined,
    initializeLife: () => Promise<LifeIdentity>,
  ): Promise<LifeIdentity | undefined> {
    this.attachHost(hostElement);
    const token = ++this.refreshGeneration;
    const snapshots = await this.loadRegistrySnapshot();
    if (!this.isCurrentRefresh(token)) {
      return undefined;
    }

    this.installRegistrySnapshot(snapshots);

    const life = await initializeLife();
    if (!this.isCurrentRefresh(token)) {
      return undefined;
    }
    await this.rebind(life);
    return life;
  }

  /** Refreshes the registry and current Life after a post-commit hint. */
  async refresh(): Promise<LifeIdentity | undefined> {
    if (this.disposed || this.hostElement === undefined) {
      return undefined;
    }
    const token = ++this.refreshGeneration;
    const snapshots = await this.loadRegistrySnapshot();

    let life: LifeIdentity | undefined;
    try {
      life = await this.options.loadCurrentLife();
    } catch {
      return undefined;
    }
    if (!this.isCurrentRefresh(token)) {
      return undefined;
    }
    this.installRegistrySnapshot(snapshots);
    if (life === undefined) {
      return undefined;
    }
    await this.rebind(life);
    return this.isCurrentRefresh(token) ? life : undefined;
  }

  /** Render a state through the currently published generation only. */
  async render(state: BodyState): Promise<void> {
    const binding = this.activeBinding;
    if (binding === undefined || this.disposed) {
      return;
    }
    try {
      const result = await binding.coordinator.render(state);
      if (!this.isCurrentBinding(binding) || !result.applied) {
        return;
      }
      this.options.onSnapshot?.(result.snapshot);
      await binding.host.render(result.snapshot);
    } catch {
      // Presentation failure remains bounded at the host/fallback boundary.
    }
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.refreshGeneration += 1;
    this.bindingGeneration += 1;
    const binding = this.activeBinding ?? this.pendingBinding;
    this.activeBinding = undefined;
    this.pendingBinding = undefined;
    if (binding !== undefined) {
      binding.host.dispose();
    }
    this.hostElement = undefined;
  }

  private async loadRegistrySnapshot(): Promise<
    readonly InstalledBodyPackageSnapshot[]
  > {
    try {
      return await this.options.loadRegistrySnapshot();
    } catch {
      // A registry read failure must not prevent the existing Life from
      // starting. The caller installs an empty snapshot, restoring the
      // bundled default-only catalog.
      return [];
    }
  }

  private installRegistrySnapshot(
    snapshots: readonly InstalledBodyPackageSnapshot[],
  ): void {
    try {
      this.options.installRegistrySnapshot(snapshots);
    } catch {
      // A malformed snapshot is fail-closed to the same default-only catalog.
      this.options.installRegistrySnapshot([]);
    }
  }

  private async rebind(life: LifeIdentity): Promise<void> {
    const generation = ++this.bindingGeneration;
    const previous = this.activeBinding ?? this.pendingBinding;
    this.activeBinding = undefined;
    this.pendingBinding = undefined;

    const retirement = this.retirementTail.then(async () => {
      if (previous === undefined) {
        return;
      }
      await previous.host.disposeAndWait();
    });
    this.retirementTail = retirement.catch(() => undefined);
    await retirement.catch(() => undefined);
    if (!this.isCurrentGeneration(generation)) {
      return;
    }

    const hostElement = this.hostElement;
    if (hostElement === undefined) {
      return;
    }

    let composition: BodyPresentationComposition;
    try {
      composition = this.options.createPresentation(life.bodyId);
    } catch {
      return;
    }
    if (!this.isCurrentGeneration(generation)) {
      return;
    }

    const candidate: ActiveBinding = {
      generation,
      bodyId: life.bodyId,
      coordinator: new BodyRenderCoordinator(composition.provider),
      host: new BodyRendererHost(composition.renderer),
    };
    this.pendingBinding = candidate;

    try {
      await candidate.host.mount(hostElement);
      if (!this.isCurrentBinding(candidate)) {
        candidate.host.dispose();
        return;
      }

      // Publish the mounted candidate before its first provider await. This
      // preserves the existing startup race contract: a state transition that
      // arrives during the initial render gets its own coordinator generation
      // and fences the older completion.
      this.pendingBinding = undefined;
      this.activeBinding = candidate;
      const initial = await candidate.coordinator.render(
        this.options.getCurrentState(),
      );
      if (!this.isCurrentBinding(candidate)) {
        candidate.host.dispose();
        return;
      }
      // A superseded provider result belongs to this still-current binding;
      // only its snapshot is stale. The newer render request owns the same
      // coordinator and will continue delivering through this host.
      if (!initial.applied) {
        return;
      }

      if (!this.isCurrentBinding(candidate)) {
        candidate.host.dispose();
        return;
      }
      this.options.onSnapshot?.(initial.snapshot);
      await candidate.host.render(initial.snapshot);
    } catch {
      if (this.pendingBinding === candidate) {
        this.pendingBinding = undefined;
      }
      if (this.activeBinding === candidate) {
        this.activeBinding = undefined;
      }
      candidate.host.dispose();
    }
  }

  private isCurrentRefresh(token: number): boolean {
    return !this.disposed && this.refreshGeneration === token;
  }

  private isCurrentGeneration(generation: number): boolean {
    return !this.disposed && this.bindingGeneration === generation;
  }

  private isCurrentBinding(binding: ActiveBinding): boolean {
    return (
      this.isCurrentGeneration(binding.generation) &&
      (this.activeBinding === binding || this.pendingBinding === binding)
    );
  }
}
