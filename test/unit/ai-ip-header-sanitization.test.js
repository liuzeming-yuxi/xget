import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import worker from '../../src/index.js';

describe('AI IP Header Sanitization', () => {
  /** @type {Request | null} */
  let upstreamRequest;

  beforeEach(() => {
    upstreamRequest = null;

    const fetchStub = vi.fn(async (input, init) => {
      const upstreamUrl = input instanceof Request ? input.url : String(input);
      upstreamRequest = new Request(upstreamUrl, init);

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json'
        }
      });
    });

    vi.stubGlobal('fetch', fetchStub);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('strips client identity and geo headers for AI requests', async () => {
    const request = new Request('https://example.com/ip/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer test-token',
        'Content-Type': 'application/json',
        'X-Forwarded-For': '1.1.1.1',
        'x-real-ip': '2.2.2.2',
        Forwarded: 'for=3.3.3.3',
        'CF-Connecting-IP': '4.4.4.4',
        'CF-IPCountry': 'CN',
        'CF-Ray': '9cb3bedb9e70b96f',
        'CF-Visitor': '{"scheme":"https"}',
        'True-Client-IP': '5.5.5.5',
        'X-Client-IP': '6.6.6.6',
        'X-Cluster-Client-IP': '7.7.7.7',
        'Fastly-Client-IP': '8.8.8.8',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'xget.alphacat.site',
        'X-Forwarded-Port': '443'
      },
      body: JSON.stringify({ model: 'gpt-5.1', input: 'hello' })
    });

    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
    const response = await worker.fetch(request, {}, ctx);

    expect(response.status).toBe(200);
    expect(upstreamRequest).toBeTruthy();

    const { headers } = /** @type {Request} */ (upstreamRequest);
    expect(headers.has('x-forwarded-for')).toBe(false);
    expect(headers.has('x-real-ip')).toBe(false);
    expect(headers.has('forwarded')).toBe(false);
    expect(headers.has('cf-connecting-ip')).toBe(false);
    expect(headers.has('cf-ipcountry')).toBe(false);
    expect(headers.has('cf-ray')).toBe(false);
    expect(headers.has('cf-visitor')).toBe(false);
    expect(headers.has('true-client-ip')).toBe(false);
    expect(headers.has('x-client-ip')).toBe(false);
    expect(headers.has('x-cluster-client-ip')).toBe(false);
    expect(headers.has('fastly-client-ip')).toBe(false);
    expect(headers.has('x-forwarded-proto')).toBe(false);
    expect(headers.has('x-forwarded-host')).toBe(false);
    expect(headers.has('x-forwarded-port')).toBe(false);
  });

  it('preserves Authorization and Content-Type for AI requests', async () => {
    const request = new Request('https://example.com/ip/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ai-token',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ model: 'gpt-5.1', input: 'hello' })
    });

    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
    const response = await worker.fetch(request, {}, ctx);

    expect(response.status).toBe(200);
    expect(upstreamRequest).toBeTruthy();

    const { headers } = /** @type {Request} */ (upstreamRequest);
    expect(headers.get('Authorization')).toBe('Bearer ai-token');
    expect(headers.get('Content-Type')).toBe('application/json');
  });

  it('keeps non-AI request behavior unchanged for forwarded IP headers', async () => {
    const request = new Request(
      'https://example.com/gh/test/repo/info/refs?service=git-upload-pack',
      {
        method: 'GET',
        headers: {
          'X-Forwarded-For': '9.9.9.9',
          'User-Agent': 'git/2.34.1'
        }
      }
    );

    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
    const response = await worker.fetch(request, {}, ctx);

    expect(response.status).toBe(200);
    expect(upstreamRequest).toBeTruthy();

    const { headers } = /** @type {Request} */ (upstreamRequest);
    expect(headers.get('x-forwarded-for')).toBe('9.9.9.9');
  });
});
