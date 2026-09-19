import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK, decodeProtectedHeader } from 'jose';

const encoder = new TextEncoder();
const maxBody = 2 * 1024 * 1024;
export function parseStrict(text) {
  const value = JSON.parse(text);
  const tokens = [...text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)].map(m => m[0]);
  const stack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '{' || t === '[') { stack.push(t === '{' ? new Set() : null); if (stack.length > 16) throw new Error('JSON too deep'); }
    else if (t === '}' || t === ']') stack.pop();
    else if (t.startsWith('"') && tokens[i + 1] === ':') {
      const key = JSON.parse(t), names = stack.at(-1);
      if (!names || names.has(key)) throw new Error('Duplicate JSON field'); names.add(key);
    }
  }
  return value;
}
export async function readBounded(response) {
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      length += value.length; if (length > maxBody) throw new Error('Response too large'); chunks.push(value);
    }
  } finally { await reader.cancel(); reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
export async function encryptRequest(key, operation, parameters, audience = 'admin') {
  const reply = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const requestId = crypto.randomUUID();
  const payload = { v: 1, requestId, issuedAt: new Date().toISOString(), serverId: key.serverId, audience, operation, parameters, replyKey: await exportJWK(reply.publicKey) };
  const body = await new CompactEncrypt(encoder.encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: key.kid, typ: 'darkvault-request+jwe', cty: 'application/json' })
    .encrypt(await importJWK(key.publicKey, 'ECDH-ES'));
  if (body.length > maxBody) throw new Error('Request too large');
  return { body, reply, payload };
}
export async function decryptResponse(body, request, status) {
  if (body.length > maxBody || body.split('.').length !== 5 || body.split('.')[0].length > 4096) throw new Error('Invalid envelope');
  if (!/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/.test(body)) throw new Error('Invalid encoding');
  for (const segment of body.split('.')) {
    const canonical = btoa(atob(segment.replace(/-/g,'+').replace(/_/g,'/'))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (canonical !== segment) throw new Error('Invalid encoding');
  }
  const encoded = body.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
  parseStrict(new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(encoded), c => c.charCodeAt(0))));
  const header = decodeProtectedHeader(body);
  const expected = ['alg', 'enc', 'epk', 'kid', 'typ', 'cty'];
  if (Object.keys(header).length !== expected.length || Object.keys(header).some(k => !expected.includes(k)) ||
      header.kid !== request.payload.requestId || header.typ !== 'darkvault-response+jwe' || header.cty !== 'application/json' ||
      header.epk?.crv !== 'P-256' || header.epk?.kty !== 'EC' || Object.keys(header.epk).some(k => !['kty','crv','x','y'].includes(k))) throw new Error('Invalid envelope');
  const { plaintext } = await compactDecrypt(body, request.reply.privateKey, { keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: ['A256GCM'] });
  if (plaintext.length > 1536 * 1024) throw new Error('Response too large');
  const response = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
  for (const k of ['v', 'requestId', 'serverId', 'audience', 'operation']) if (response[k] !== request.payload[k]) throw new Error('Mismatched response');
  if (response.status !== status) throw new Error('Mismatched status');
  if (response.error) throw new Error(response.error.code);
  if (status < 200 || status >= 300 || !response.data) throw new Error('Invalid response');
  return response.data;
}
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
