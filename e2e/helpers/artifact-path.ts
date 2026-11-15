// e2e/helpers/artifact-path.ts
// Where a spec writes a screenshot for a human to look at. E2E_ARTIFACT_DIR names a directory when the runner wants the files in one
// place; without it the file goes to the test's own output folder, which exists on every machine (a hard-coded /opt/cursor/artifacts does not).
import path from 'node:path';
import type { TestInfo } from '@playwright/test';

export function artifactPath(testInfo: TestInfo, name: string): string {
  const dir = process.env.E2E_ARTIFACT_DIR;
  return dir ? path.join(dir, name) : testInfo.outputPath(name);
}
