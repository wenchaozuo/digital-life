import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type {
  ActiveModelProfile,
  CreateModelProfileRequest,
  ModelConnectionTestResult,
  ModelProfile,
  ModelPurpose,
  UpdateModelProfileRequest,
} from "../src/model/modelProfileService.ts";
import {
  ModelProfileController,
  errorFromUnknown,
  type IModelProfileService,
} from "../src/settings/model/modelProfileController.ts";
import type {
  CredentialPurpose,
  ICredentialService,
} from "../src/settings/model/credentialService.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface Calls {
  lists: (ModelPurpose | null)[];
  creates: CreateModelProfileRequest[];
  updates: UpdateModelProfileRequest[];
  deletedProfiles: string[];
  setActive: { purpose: ModelPurpose; profileId: string }[];
  activeReads: ModelPurpose[];
  tests: { profileId: string; purpose: ModelPurpose }[];
  credentialSaves: { purpose: CredentialPurpose; profileId: string; apiKey: string }[];
  credentialDeletes: { purpose: CredentialPurpose; profileId: string }[];
  credentialHas: { purpose: CredentialPurpose; profileId: string }[];
}

function profile(id: string, purpose: ModelPurpose): ModelProfile {
  return {
    id,
    purpose,
    providerKind: "openai_compatible",
    displayName: `${purpose}-${id}`,
    baseUrl: "https://example.invalid/v1",
    modelName: `${purpose}-model`,
    temperature: purpose === "chat" ? 0.7 : null,
    maxTokens: purpose === "chat" ? 4096 : null,
    embeddingDimension: purpose === "embedding" ? 1536 : null,
    createdAt: "2026-07-13T00:00:00Z",
    updatedAt: "2026-07-13T00:00:00Z",
  };
}

function credentialPurpose(purpose: ModelPurpose): CredentialPurpose {
  return purpose === "chat" ? "CHAT_MODEL_API_KEY" : "EMBEDDING_MODEL_API_KEY";
}

function createMocks(initial: readonly ModelProfile[]) {
  const profiles = [...initial];
  const active = new Map<ModelPurpose, ActiveModelProfile>();
  const credentials = new Set<string>();
  const calls: Calls = {
    lists: [],
    creates: [],
    updates: [],
    deletedProfiles: [],
    setActive: [],
    activeReads: [],
    tests: [],
    credentialSaves: [],
    credentialDeletes: [],
    credentialHas: [],
  };
  const key = (purpose: CredentialPurpose, profileId: string) => `${purpose}:${profileId}`;

  const modelService: IModelProfileService = {
    async create(request) {
      calls.creates.push(request);
      const created = profile(`created-${profiles.length + 1}`, request.purpose);
      created.displayName = request.displayName;
      created.baseUrl = request.baseUrl;
      created.modelName = request.modelName;
      created.temperature = request.temperature ?? null;
      created.maxTokens = request.maxTokens ?? null;
      created.embeddingDimension = request.embeddingDimension ?? null;
      profiles.push(created);
      return created;
    },
    async update(request) {
      calls.updates.push(request);
      const existing = profiles.find((candidate) => candidate.id === request.profileId);
      if (!existing) {
        throw { code: "PROFILE_NOT_FOUND", message: "Missing profile" };
      }
      existing.displayName = request.displayName;
      existing.baseUrl = request.baseUrl;
      existing.modelName = request.modelName;
      existing.temperature = request.temperature ?? null;
      existing.maxTokens = request.maxTokens ?? null;
      existing.embeddingDimension = request.embeddingDimension ?? null;
      existing.updatedAt = "2026-07-13T01:00:00Z";
      return { ...existing };
    },
    async list(purpose) {
      calls.lists.push(purpose);
      return profiles.filter((candidate) => purpose === null || candidate.purpose === purpose);
    },
    async delete(profileId) {
      calls.deletedProfiles.push(profileId);
      const index = profiles.findIndex((candidate) => candidate.id === profileId);
      if (index >= 0) {
        profiles.splice(index, 1);
      }
      for (const [purpose, current] of active) {
        if (current.profileId === profileId) {
          active.delete(purpose);
        }
      }
      return { profileId, deleted: index >= 0 };
    },
    async setActive(purpose, profileId) {
      calls.setActive.push({ purpose, profileId });
      const value = { purpose, profileId };
      active.set(purpose, value);
      return value;
    },
    async getActive(purpose) {
      calls.activeReads.push(purpose);
      return active.get(purpose) ?? null;
    },
    async testConnection(request) {
      calls.tests.push(request);
      return {
        profileId: request.profileId,
        purpose: request.purpose,
        success: true,
        providerKind: "openai_compatible",
        modelName: "test-model",
        latencyMs: 4,
        embeddingDimension: request.purpose === "embedding" ? 1536 : null,
        errorCode: null,
        errorMessage: null,
      } satisfies ModelConnectionTestResult;
    },
  };

  const credentialService: ICredentialService = {
    async save(purpose, profileId, apiKey) {
      const resolvedPurpose = credentialPurpose(purpose);
      calls.credentialSaves.push({
        purpose: resolvedPurpose,
        profileId,
        apiKey,
      });
      credentials.add(key(resolvedPurpose, profileId));
      return { purpose: resolvedPurpose, profileId, exists: true, updated: true };
    },
    async has(purpose, profileId) {
      const resolvedPurpose = credentialPurpose(purpose);
      calls.credentialHas.push({ purpose: resolvedPurpose, profileId });
      return {
        purpose: resolvedPurpose,
        profileId,
        exists: credentials.has(key(resolvedPurpose, profileId)),
      };
    },
    async delete(purpose, profileId) {
      const resolvedPurpose = credentialPurpose(purpose);
      calls.credentialDeletes.push({ purpose: resolvedPurpose, profileId });
      const deleted = credentials.delete(key(resolvedPurpose, profileId));
      return { purpose: resolvedPurpose, profileId, exists: false, deleted };
    },
  };

  return { calls, credentials, modelService, credentialService };
}

test("1. Chat 与 Embedding 档案按 purpose 隔离且不自动选择", async () => {
  const chat = profile("chat-1", "chat");
  const embedding = profile("embedding-1", "embedding");
  const mocks = createMocks([chat, embedding]);
  const chatController = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  const embeddingController = new ModelProfileController("embedding", mocks.modelService, mocks.credentialService);

  await Promise.all([chatController.refresh(), embeddingController.refresh()]);
  assert.deepEqual(chatController.profiles.map((item) => item.id), ["chat-1"]);
  assert.deepEqual(embeddingController.profiles.map((item) => item.id), ["embedding-1"]);
  assert.equal(chatController.activeProfile, null);
  assert.equal(embeddingController.activeProfile, null);
  assert.deepEqual(mocks.calls.lists, ["chat", "embedding"]);
});

test("2. 空列表不创建默认档案", async () => {
  const mocks = createMocks([]);
  const controller = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  await controller.refresh();
  assert.equal(controller.profiles.length, 0);
  assert.equal(mocks.calls.creates.length, 0);
});

test("3. 创建请求只发送当前 purpose 的参数", async () => {
  const mocks = createMocks([]);
  const chat = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  const embedding = new ModelProfileController("embedding", mocks.modelService, mocks.credentialService);
  await chat.saveProfile({
    purpose: "chat",
    displayName: "Chat",
    baseUrl: "https://chat.example/v1",
    modelName: "chat-model",
    temperature: 0.4,
    maxTokens: 320,
  });
  await embedding.saveProfile({
    purpose: "embedding",
    displayName: "Embedding",
    baseUrl: "https://embedding.example/v1",
    modelName: "embedding-model",
    embeddingDimension: 1536,
  });
  assert.equal(mocks.calls.creates[0]?.purpose, "chat");
  assert.equal("embeddingDimension" in (mocks.calls.creates[0] ?? {}), false);
  assert.equal(mocks.calls.creates[1]?.purpose, "embedding");
  assert.equal("temperature" in (mocks.calls.creates[1] ?? {}), false);
  assert.equal("maxTokens" in (mocks.calls.creates[1] ?? {}), false);
  assert.equal("apiKey" in (mocks.calls.creates[0] ?? {}), false);
});

test("4. 编辑以后端响应和刷新列表为准", async () => {
  const chat = profile("chat-1", "chat");
  const mocks = createMocks([chat]);
  const controller = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  await controller.refresh();
  const result = await controller.saveProfile(
    {
      purpose: "chat",
      displayName: "Updated",
      baseUrl: "https://updated.example/v1",
      modelName: "updated-model",
      temperature: 0.9,
      maxTokens: 512,
    },
    chat.id,
  );
  assert.equal(result?.displayName, "Updated");
  assert.equal(controller.profiles[0]?.modelName, "updated-model");
  assert.equal(mocks.calls.updates.length, 1);
  assert.ok(mocks.calls.lists.length >= 2);
});

test("5. 凭据保存、删除和 purpose 均受隔离且不进入模型请求", async () => {
  const chat = profile("chat-1", "chat");
  const embedding = profile("embedding-1", "embedding");
  const mocks = createMocks([chat, embedding]);
  const chatController = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  const embeddingController = new ModelProfileController("embedding", mocks.modelService, mocks.credentialService);
  await Promise.all([chatController.refresh(), embeddingController.refresh()]);
  assert.equal(await chatController.saveCredential(chat.id, "component-only-placeholder"), true);
  assert.equal(await embeddingController.saveCredential(embedding.id, "component-only-placeholder"), true);
  assert.deepEqual(
    mocks.calls.credentialSaves.map((call) => call.purpose),
    ["CHAT_MODEL_API_KEY", "EMBEDDING_MODEL_API_KEY"],
  );
  assert.equal(await chatController.deleteCredential(chat.id), true);
  assert.ok(mocks.calls.credentialHas.length >= 4);
  assert.equal(mocks.calls.creates.some((request) => "apiKey" in request), false);
});

test("6. 设置活动档案后重新读取后端状态", async () => {
  const chat = profile("chat-1", "chat");
  const mocks = createMocks([chat]);
  const controller = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  await controller.refresh();
  const readsBefore = mocks.calls.activeReads.length;
  assert.equal(await controller.setActive(chat.id), true);
  assert.equal(controller.activeProfile?.profileId, chat.id);
  assert.equal(mocks.calls.activeReads.length, readsBefore + 1);
});

test("7. 没有凭据时不调用连接测试；单卡测试不锁死其他卡", async () => {
  const first = profile("chat-1", "chat");
  const second = profile("chat-2", "chat");
  const mocks = createMocks([first, second]);
  const controller = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  await controller.refresh();
  assert.equal(await controller.testConnection(first.id), undefined);
  assert.equal(mocks.calls.tests.length, 0);
  await controller.saveCredential(first.id, "component-only-placeholder");
  await controller.testConnection(first.id);
  assert.equal(mocks.calls.tests.length, 1);
  assert.equal(controller.cardState(first.id).state, "succeeded");
  assert.equal(controller.cardState(second.id).state, "idle");
});

test("8. 存在凭据时阻止删除档案，删除凭据后才允许", async () => {
  const chat = profile("chat-1", "chat");
  const mocks = createMocks([chat]);
  const controller = new ModelProfileController("chat", mocks.modelService, mocks.credentialService);
  await controller.refresh();
  await controller.saveCredential(chat.id, "component-only-placeholder");
  assert.equal(await controller.deleteProfile(chat.id), false);
  assert.equal(mocks.calls.deletedProfiles.length, 0);
  assert.equal(controller.cardState(chat.id).error?.code, "CREDENTIAL_EXISTS");
  await controller.deleteCredential(chat.id);
  assert.equal(await controller.deleteProfile(chat.id), true);
  assert.deepEqual(mocks.calls.deletedProfiles, [chat.id]);
});

test("9. 表单丢弃、密钥清理和无明文读取调用在组件中受约束", () => {
  const formSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/ModelProfileForm.vue"),
    "utf8",
  );
  const cardSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/ModelProfileCard.vue"),
    "utf8",
  );
  const viewSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/ModelProfilesView.vue"),
    "utf8",
  );
  assert.match(formSource, /dirtyChange/);
  assert.match(viewSource, /Discard unsaved model profile changes/);
  assert.match(viewSource, /function closeForm[\s\S]*clearSensitiveInputs/);
  assert.match(cardSource, /clearSensitiveInput/);
  assert.match(viewSource, /visibilitychange/);
  assert.match(cardSource, /Delete the saved API Key/);
  assert.doesNotMatch(cardSource, /get_api_key|read_credential|localStorage|sessionStorage/);
});

test("10. 凭据操作错误不会回显当前输入", () => {
  const error = errorFromUnknown(
    { code: "CREDENTIAL_ERROR", message: "component-only-placeholder" },
    "saveCredential",
  );
  assert.equal(error.code, "CREDENTIAL_ERROR");
  assert.doesNotMatch(error.safeMessage, /component-only-placeholder/);
});
