import { invoke } from "@tauri-apps/api/core";

export type BodyPackageStatus = "available" | "corrupt-unavailable";

export interface InstallLive2DBodyPackageRequest {
  sourcePath: string;
  displayName: string;
}

export interface BodyPackageAssetSnapshot {
  relativePath: string;
  assetKind: string;
  contentHash: string;
  sizeBytes: number;
}

export interface InstalledBodyPackageSnapshot {
  bodyId: string;
  displayName: string;
  presentationKind: "live2d";
  modelEntry: string;
  packageContentHash: string;
  packageVersion: number;
  installedAt: string;
  status: BodyPackageStatus;
  assets: BodyPackageAssetSnapshot[];
}

/**
 * Narrow frontend boundary for the managed body-package registry.  The
 * backend remains the authority for package validation, storage, and serving;
 * this service only transports the registry DTOs and backend asset URL.
 */
export class BodyPackageService {
  async install(
    request: InstallLive2DBodyPackageRequest,
  ): Promise<InstalledBodyPackageSnapshot> {
    return invoke<InstalledBodyPackageSnapshot>(
      "install_live2d_body_package",
      { request },
    );
  }

  async list(): Promise<InstalledBodyPackageSnapshot[]> {
    return invoke<InstalledBodyPackageSnapshot[]>("list_body_packages");
  }

  async get(bodyId: string): Promise<InstalledBodyPackageSnapshot | null> {
    return invoke<InstalledBodyPackageSnapshot | null>("get_body_package", {
      bodyId,
    });
  }

  async delete(bodyId: string): Promise<void> {
    await invoke("delete_body_package", { bodyId });
  }

  async getRegistrySnapshot(): Promise<InstalledBodyPackageSnapshot[]> {
    return invoke<InstalledBodyPackageSnapshot[]>(
      "get_body_package_registry_snapshot",
    );
  }
}

export const bodyPackageService = new BodyPackageService();
