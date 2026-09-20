import { parseStrict, readBounded, encryptRequest, decryptResponse } from '@darkvault/client/protocol';
export { parseStrict, readBounded, encryptRequest, decryptResponse };

export async function execute(operation, parameters, csrfToken) {
  const signal = AbortSignal.timeout(30000);
  const discovery = await fetch('/api/v1/crypto/key', { signal, redirect: 'error', cache: 'no-store' });
  if (!discovery.ok) throw new Error('Key unavailable');
  const key = parseStrict(await readBounded(discovery));
  if (key.protocolVersion !== 1 || Date.parse(key.notAfter) <= Date.now()) throw new Error('Invalid server key');
  const request = await encryptRequest(key, operation, parameters);
  const response = await fetch('/admin/api/v1/execute', { method: 'POST', signal, redirect: 'error', headers: { 'Content-Type': 'application/jose', 'X-CSRF-Token': csrfToken }, body: request.body });
  const body = await readBounded(response);
  if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose') throw new Error(response.status === 401 ? 'Session expired. Sign in again.' : 'Request rejected');
  return decryptResponse(body, request, response.status);
}
