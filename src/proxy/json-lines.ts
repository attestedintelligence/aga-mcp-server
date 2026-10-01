/** Byte-bounded newline framing with fatal UTF-8 decoding. Bounds each frame, not an entire TCP chunk. */
export class JsonLineFramer {
  private parts: Buffer[] = [];
  private bytes = 0;
  constructor(private readonly maximum: number) {}
  push(chunk: Buffer): string[] {
    const lines: string[] = [];
    let start = 0;
    for (;;) {
      const end = chunk.indexOf(10, start);
      const part = chunk.subarray(start, end < 0 ? chunk.length : end);
      this.bytes += part.length;
      if (this.bytes > this.maximum) throw new Error('Message exceeds byte limit');
      if (part.length) this.parts.push(part);
      if (end < 0) break;
      const bytes = Buffer.concat(this.parts, this.bytes);
      this.parts = []; this.bytes = 0;
      const line = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
      if (line) lines.push(line);
      start = end + 1;
    }
    return lines;
  }
}
