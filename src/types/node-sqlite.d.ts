// Minimal ambient types for Node's built-in `node:sqlite` (experimental; available at runtime on
// Node 22 — the node:22-alpine prod image — but NOT yet in this repo's pinned @types/node@^20).
// Covers ONLY the synchronous surface mailbox-store.ts uses. Delete this shim when the project
// bumps @types/node to a version that ships node:sqlite (22.x), which supersedes it.
declare module 'node:sqlite' {
  interface StatementSync {
    run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  }
  export class DatabaseSync {
    constructor(path: string, options?: { open?: boolean; readOnly?: boolean });
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
