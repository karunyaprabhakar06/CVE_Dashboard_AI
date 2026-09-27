import { Agent, ProxyAgent, setGlobalDispatcher } from 'undici';

// Set global proxy dispatcher if proxy env vars are set
const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.https_proxy || process.env.http_proxy;
if (proxyUrl) {
  setGlobalDispatcher(new ProxyAgent({
    uri: proxyUrl,
    connect: { rejectUnauthorized: false },
  }));
  console.log('[proxy] global fetch dispatcher set:', proxyUrl);
}

const DEFAULT_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS ?? 15_000);

export function fetchWithTimeout(url, init = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...init, signal: controller.signal }).finally(() => {
    clearTimeout(timer);
  });
}
