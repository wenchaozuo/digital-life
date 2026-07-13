import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const filesToCheck = [
  'src/chat/memoryReviewController.ts',
  'tests/memoryReview.test.ts',
  'src/settings/model/credentialService.ts',
  'src/settings/model/modelProfileController.ts',
  'src/settings/model/ModelProfileForm.vue',
  'src/settings/model/ModelProfileCard.vue',
  'src/settings/model/ModelProfilesView.vue',
  'src/settings/model/memoryVectorIndexService.ts',
  'src/settings/model/memoryVectorIndexController.ts',
  'src/settings/model/MemoryVectorIndexPanel.vue',
  'src/model/modelService.ts',
  'src/conversation/conversationService.ts',
  'src/conversation/conversationHistoryService.ts',
  'src/conversation/types.ts',
  'src/chat/ChatView.vue',
  'tests/modelSettings.test.ts',
  'tests/memoryVectorIndexSettings.test.ts',
  'tests/conversationPersistence.test.ts',
  'src/settings/memory/memoryCenterController.ts',
  'src/settings/memory/MemoryCenterView.vue',
  'src/settings/memory/MemoryListPanel.vue',
  'src/settings/memory/MemoryDetailPanel.vue',
  'tests/memoryCenterController.test.ts'
];

let failed = false;

for (const file of filesToCheck) {
  const filePath = path.resolve(process.cwd(), file);
  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${file}`);
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  lines.forEach((line, index) => {
    const cleanLine = line.replace(/\/\/.*$/, '').replace(/\/\*.*?\*\//g, '');

    if (/:\s*any\b/.test(cleanLine)) {
      console.error(`Error: Found ": any" in ${file} at line ${index + 1}: ${line.trim()}`);
      failed = true;
    }
    if (/\bas\s+any\b/.test(cleanLine)) {
      console.error(`Error: Found "as any" in ${file} at line ${index + 1}: ${line.trim()}`);
      failed = true;
    }
    if (/<\s*any\s*>/.test(cleanLine)) {
      console.error(`Error: Found "<any>" in ${file} at line ${index + 1}: ${line.trim()}`);
      failed = true;
    }
    if (/@ts-ignore/.test(cleanLine)) {
      console.error(`Error: Found "@ts-ignore" in ${file} at line ${index + 1}: ${line.trim()}`);
      failed = true;
    }
  });
}

if (failed) {
  console.error("Explicit any check failed!");
  process.exit(1);
} else {
  console.log("No explicit any or ts-ignore found. Pass!");
  process.exit(0);
}
