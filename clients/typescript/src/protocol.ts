import type { JWK } from 'jose';
import { DarkVaultError } from './errors.js';
import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK, decodeProtectedHeader } from 'jose';

const encoder = new TextEncoder();
const maxBody = 2 * 1024 * 1024;
export function parseStrict(text: string) {
  if (encoder.encode(text).length > 1536 * 1024) throw new Error('JSON too large');
  const value = JSON.parse(text);
  const tokens = [...text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)].map(m => m[0]);
  const stack: (Set<string> | null)[] = [];
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
export async function readBounded(response: Response) {
  if (!response.body) throw new Error('Missing response body');
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
export async function encryptRequest(key: {serverId: string; kid: string; publicKey: JWK}, operation: string, parameters: unknown, audience = 'admin') {
  const reply = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const requestId = crypto.randomUUID();
  const payload = { v: 1, requestId, issuedAt: new Date().toISOString(), serverId: key.serverId, audience, operation, parameters, replyKey: await exportJWK(reply.publicKey) };
  const plaintext = JSON.stringify(payload);
  parseStrict(plaintext);
  const body = await new CompactEncrypt(encoder.encode(plaintext))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: key.kid, typ: 'darkvault-request+jwe', cty: 'application/json' })
    .encrypt(await importJWK(key.publicKey, 'ECDH-ES'));
  if (body.length > maxBody) throw new Error('Request too large');
  return { body, reply, payload };
}
export async function decryptResponse(body: string, request: Awaited<ReturnType<typeof encryptRequest>>, status: number) {
  if (body.length > maxBody || body.split('.').length !== 5 || body.split('.')[0].length > 4096) throw new Error('Invalid envelope');
  if (!/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/.test(body)) throw new Error('Invalid encoding');
  for (const segment of body.split('.')) {
    const canonical = btoa(atob(segment.replace(/-/g,'+').replace(/_/g,'/'))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (canonical !== segment) throw new Error('Invalid encoding');
  }
  const encoded = body.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
  parseStrict(new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(encoded), c => c.charCodeAt(0))));
  const header = decodeProtectedHeader(body);
  const epk = header.epk as JWK | undefined;
  const expected = ['alg', 'enc', 'epk', 'kid', 'typ', 'cty'];
  if (Object.keys(header).length !== expected.length || Object.keys(header).some(k => !expected.includes(k)) ||
      header.kid !== request.payload.requestId || header.typ !== 'darkvault-response+jwe' || header.cty !== 'application/json' ||
      epk?.crv !== 'P-256' || epk?.kty !== 'EC' || Object.keys(epk).sort().join(',') !== 'crv,kty,x,y') throw new Error('Invalid envelope');
  const { plaintext } = await compactDecrypt(body, request.reply.privateKey, { keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: ['A256GCM'] });
  if (plaintext.length > 1536 * 1024) throw new Error('Response too large');
  const response = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
  if (!response || typeof response !== 'object' || Array.isArray(response)) throw new Error('Invalid response');
  for (const k of ['v', 'requestId', 'serverId', 'audience', 'operation'] as const) if (response[k] !== request.payload[k]) throw new Error('Mismatched response');
  if (response.status !== status) throw new Error('Mismatched status');
  if (!Object.prototype.hasOwnProperty.call(response, 'error')) throw new Error('Invalid response');
  if (response.error !== null) {
    if (!response.error || typeof response.error !== 'object' || typeof response.error.code !== 'string' || typeof response.error.message !== 'string') throw new Error('Invalid response error');
    throw new DarkVaultError(response.error.code, status, request.payload.requestId);
  }
  if (status < 200 || status >= 300 || !response.data || typeof response.data !== 'object' || Array.isArray(response.data)) throw new Error('Invalid response');
  return response.data;
}
