import test from "node:test";
import assert from "node:assert/strict";

import { ConversationSession } from "../src/conversation/session/conversationSession.ts";
import { MemoryExtractor } from "../src/memory/extractor/memoryExtractorService.ts";
import {
  MemoryKinds,
  MemorySourceTypes,
  MemoryStatuses,
} from "../src/memory/types.ts";

const timestamp = "2026-07-11T00:00:00.000Z";

function extract(lifeId: string, ...contents: string[]) {
  return new MemoryExtractor().extract({
    lifeId,
    sourceType: MemorySourceTypes.Conversation,
    messages: contents.map((content) => ({
      role: "user" as const,
      content,
      timestamp,
    })),
  });
}

test("explicit preference creates a preference candidate", () => {
  const result = extract("life-a", "我喜欢喝乌龙茶");
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].kind, MemoryKinds.Preference);
  assert.equal(result.candidates[0].summary, "Preference: 喜欢喝乌龙茶");
});

test("explicit fact creates a fact candidate", () => {
  const result = extract("life-a", "我的职业是软件工程师");
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].kind, MemoryKinds.Fact);
  assert.equal(result.candidates[0].summary, "Fact: 职业: 软件工程师");
});

test("explicit goal creates a goal candidate", () => {
  const result = extract("life-a", "我要学习Rust");
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].kind, MemoryKinds.Goal);
  assert.equal(result.candidates[0].confidence, 0.95);
});

test("ordinary chat and assistant text create no candidates", () => {
  const extractor = new MemoryExtractor();
  const result = extractor.extract({
    lifeId: "life-a",
    sourceType: MemorySourceTypes.Conversation,
    messages: [
      { role: "user", content: "今天天气不错", timestamp },
      { role: "assistant", content: "我喜欢替用户做决定", timestamp },
    ],
  });
  assert.deepEqual(result.candidates, []);
});

test("hard sensitive information is rejected instead of becoming a candidate", () => {
  const result = extract(
    "life-a",
    "我的密码是[已隐藏]",
    "我的地址是示例路1号",
  );
  assert.deepEqual(result.candidates, []);
  assert.equal(result.rejectedSensitiveCount, 2);
});

test("possibly sensitive facts are marked and remain candidates only", () => {
  const result = extract("life-a", "我的邮箱是person@example.test");
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].isSensitive, true);
  assert.equal(result.candidates[0].status, MemoryStatuses.Candidate);
});

test("every generated item has candidate status and conversation source", () => {
  const result = extract(
    "life-a",
    "我喜欢安静的音乐",
    "我是程序员",
    "我想学习绘画",
  );
  assert.ok(result.candidates.length > 0);
  assert.ok(
    result.candidates.every(
      ({ status, sourceType }) =>
        status === MemoryStatuses.Candidate &&
        sourceType === MemorySourceTypes.Conversation,
    ),
  );
});

test("life ids remain isolated in extraction results", () => {
  const lifeA = extract("life-a", "我喜欢茶");
  const lifeB = extract("life-b", "我喜欢茶");
  assert.ok(lifeA.candidates.every(({ lifeId }) => lifeId === "life-a"));
  assert.ok(lifeB.candidates.every(({ lifeId }) => lifeId === "life-b"));
});

test("same request produces exactly the same result", () => {
  const first = extract("life-a", "我通常早上阅读；我会编写TypeScript");
  const second = extract("life-a", "我通常早上阅读；我会编写TypeScript");
  assert.deepEqual(first, second);
});

test("extracting session messages neither mutates the session nor persists data", () => {
  const session = new ConversationSession(20, "session-1", timestamp);
  session.addMessage({
    role: "user",
    content: "我喜欢散步",
    timestamp,
  });
  const before = session.getMessages();

  new MemoryExtractor().extract({
    lifeId: "life-a",
    sourceType: MemorySourceTypes.Conversation,
    messages: before,
  });

  assert.deepEqual(session.getMessages(), before);
});
