import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchBundleViaControl } from '../../src/proxy/control.js';

const locator = { host: '127.0.0.1', port: 18801, pid: 1 };
const shape = { algorithm: 'Ed25519-SHA256-JCS', receipts: [], checkpoint: { merkle_root: '', signature: '' } };
const headers = { 'x-aga-control': 'aga-proxy', 'content-type': 'application/json' };
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('control client byte and network boundaries', () => {
  it('uses one deadline and refuses redirects before receiving an export', async () => {
    const fetcher = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect(init?.redirect).toBe('error');
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      return new Response(JSON.stringify(shape), { headers });
    });
    vi.stubGlobal('fetch', fetcher);
    expect(await fetchBundleViaControl(locator)).toEqual(shape);
  });

  it.each(['example.com', '127.0.0.1@external.example', '127.0.0.1/path', '[::1]'])('refuses unsupported locator host %s before networking', async host => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify(shape), { headers }));
    vi.stubGlobal('fetch', fetcher);
    await expect(fetchBundleViaControl({ ...locator, host })).rejects.toThrow(/loopback/);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([0, -1, 65536, 1.5, NaN])('refuses invalid port %s before networking', async port => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify(shape), { headers }));
    vi.stubGlobal('fetch', fetcher);
    await expect(fetchBundleViaControl({ ...locator, port })).rejects.toThrow(/port/);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects invalid UTF-8 instead of silently rewriting it in JSON strings', async () => {
    const bytes = Buffer.concat([Buffer.from(JSON.stringify(shape).slice(0, -1) + ',"label":"'), Buffer.from([255]), Buffer.from('"}')]);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(bytes, { headers })));
    await expect(fetchBundleViaControl(locator)).rejects.toThrow(/UTF-8/);
  });

  it('stops a body at 32 MiB even without a declared content length', async () => {
    let pulls = 0;
    const chunk = new Uint8Array(64 * 1024).fill(32);
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ pull(c) { if (++pulls <= 600) c.enqueue(chunk); else c.close(); }, cancel });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { headers })));
    await expect(fetchBundleViaControl(locator)).rejects.toThrow(/32 MiB/);
    expect(pulls).toBeLessThanOrEqual(515);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('cancels a stalled body by the shared deadline and releases its reader', async () => {
    vi.useFakeTimers();
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const body = new ReadableStream<Uint8Array>({ pull() {}, cancel });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { headers })));
    const outcome = fetchBundleViaControl(locator).then(() => 'unexpected success', error => String(error));
    await vi.advanceTimersByTimeAsync(15_001);
    expect(await outcome).toMatch(/15 second/);
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});
