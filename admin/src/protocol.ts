import { parseStrict, readBounded, encryptRequest, decryptResponse, validateServerKey, parsePlainError, retryAfterMs } from '@darkvault/client/protocol';
import { DarkVaultError } from '@darkvault/client';
import type { ServerKey } from '@darkvault/client/protocol';
export { parseStrict, readBounded, encryptRequest, decryptResponse };

let cachedKey: ServerKey | undefined;
let cacheUntil = 0;
export async function execute<T = unknown>(operation: string, parameters: object, csrfToken: string): Promise<T> {
  const signal = AbortSignal.timeout(30000);
  let keyRetry = false;
  while (true) {
    if (!cachedKey || cacheUntil <= Date.now() || Date.parse(cachedKey.notAfter) <= Date.now()) {
      const discovery = await fetch('/api/v1/crypto/key', { signal, redirect: 'error', cache: 'no-store' });
      if (!discovery.ok) { await discovery.body?.cancel(); throw new DarkVaultError('key_unavailable', discovery.status); }
      cachedKey = validateServerKey(parseStrict(await readBounded(discovery)));
      cacheUntil = Math.min(Date.now() + 300000, Date.parse(cachedKey.notAfter));
    }
    const request = await encryptRequest(cachedKey, operation, parameters);
    const response = await fetch('/admin/api/v1/execute', { method: 'POST', signal, redirect: 'error', headers: { 'Content-Type': 'application/jose', 'Accept': 'application/jose', 'X-CSRF-Token': csrfToken }, body: request.body });
    if (response.status === 401) { await response.body?.cancel(); throw new Error('Session expired. Sign in again.'); }
    const body = await readBounded(response);
    if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose') {
      const code = parsePlainError(body);
      if (response.status === 400 && code === 'unknown_key' && !keyRetry) { cachedKey = undefined; cacheUntil = 0; keyRetry = true; continue; }
      throw new DarkVaultError(code, response.status, request.payload.requestId, retryAfterMs(response.headers.get('Retry-After')));
    }
    return await decryptResponse(body, request, response.status) as T;
  }
}
