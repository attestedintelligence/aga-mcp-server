/** Reject ambiguous member names and excessive nesting before JSON.parse. */
export function parseUnambiguousJson(raw: string): unknown {
  let at = 0, nodes = 0;
  const fail = (): never => { throw new SyntaxError('Invalid or ambiguous JSON'); };
  const space = () => { while (at < raw.length && /[\x20\t\r\n]/.test(raw[at]!)) at++; };
  const string = (): string => {
    const start = at++;
    while (at < raw.length) {
      const c = raw[at++]!;
      if (c === '"') return JSON.parse(raw.slice(start, at)) as string;
      if (c === '\\') at++;
    }
    return fail();
  };
  const value = (depth: number): void => {
    // Higher than the signed-argument canonicalization limit so attributable tool
    // requests still reach the existing DENIED-receipt path for excessive depth.
    if (depth > 1024 || ++nodes > 100000) fail();
    space(); const c = raw[at];
    if (c === '"') { string(); return; }
    if (c === '{' || c === '[') {
      const object = c === '{', close = object ? '}' : ']';
      const names = new Set<string>(); at++; space();
      if (raw[at] === close) { at++; return; }
      for (;;) {
        space();
        if (object) {
          if (raw[at] !== '"') fail();
          const key = string(); if (names.has(key)) fail(); names.add(key);
          space(); if (raw[at++] !== ':') fail();
        }
        value(depth + 1); space();
        if (raw[at] === close) { at++; return; }
        if (raw[at++] !== ',') fail();
      }
    }
    const match = /^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(raw.slice(at));
    if (!match) fail(); else at += match[0].length;
  };
  value(0); space(); if (at !== raw.length) fail();
  return JSON.parse(raw) as unknown;
}
