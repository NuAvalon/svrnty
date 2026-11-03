// Helpers for the static guards over UI source files. Moved here, unchanged, from contact-update-fresh-read.test.ts so the guard over
// app/page.tsx uses the same walker.

// The text of every `name(...)` call in `text`, found by balanced parentheses (string and template literals are skipped, and so are // and /* */
// comments inside the call, so an apostrophe or a parenthesis in a comment cannot start a string or end the call early), so a nested call or a
// multi-line body cannot cut the match short.
export function callsOf(text: string, name: string): string[] {
  const out: string[] = [];
  const open = name + '(';
  for (let at = text.indexOf(open); at !== -1; at = text.indexOf(open, at + 1)) {
    if (at > 0 && /[\w.$]/.test(text[at - 1])) continue; // a longer identifier, or a method of something else
    let depth = 0;
    let i = at + name.length;
    for (; i < text.length; i++) {
      const ch = text[i];
      if (ch === '/' && text[i + 1] === '/') {
        for (i += 2; i < text.length && text[i] !== '\n'; i++);
        continue;
      }
      if (ch === '/' && text[i + 1] === '*') {
        const end = text.indexOf('*/', i + 2);
        i = end === -1 ? text.length : end + 1;
        continue;
      }
      if (ch === "'" || ch === '"' || ch === '`') {
        for (i++; i < text.length && text[i] !== ch; i++) if (text[i] === '\\') i++;
        continue;
      }
      if (ch === '(') depth++;
      else if (ch === ')' && --depth === 0) break;
    }
    out.push(text.slice(at, i + 1));
  }
  return out;
}
