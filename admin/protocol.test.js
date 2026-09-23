import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { compactDecrypt, CompactEncrypt, importJWK } from 'jose';
import { encryptRequest, decryptResponse, parseStrict } from './dist/protocol.js';

test('Reject duplicate fields, escaped duplicate names and excess nesting',()=>{
  assert.throws(()=>parseStrict('{"a":1,"a":2}'));
  assert.throws(()=>parseStrict('{"a":1,"\\u0061":2}'));
  assert.throws(()=>parseStrict('['.repeat(17)+'0'+']'.repeat(17)));
  assert.deepEqual(parseStrict('{"a":{"a":1},"b":["x:y"]}'),{a:{a:1},b:['x:y']});
});

test('Decrypt the .NET fixture and reject tampering', async () => {
  const fixture=JSON.parse(await readFile('../tests/fixtures/jwe.json','utf8'));
  const key=await importJWK(fixture.jwk,'ECDH-ES');
  const decoded=await compactDecrypt(fixture.compact,key,{keyManagementAlgorithms:['ECDH-ES'],contentEncryptionAlgorithms:['A256GCM']});
  assert.equal(new TextDecoder().decode(decoded.plaintext),fixture.plaintext);
  const parts=fixture.compact.split('.');parts[4]='AAAAAAAAAAAAAAAAAAAAAA';
  await assert.rejects(compactDecrypt(parts.join('.'),key));
});
test('Bind a response to its request',async()=>{
  const fixture=JSON.parse(await readFile('../tests/fixtures/jwe.json','utf8'));
  const {d,...publicKey}=fixture.jwk;
  const request=await encryptRequest({serverId:'test-server',kid:'test',publicKey},'bucket.list',{});
  const reply=await importJWK(request.payload.replyKey,'ECDH-ES');
  const payload={...request.payload,status:200,data:{items:[]},error:null}; delete payload.parameters;delete payload.replyKey;
  const compact=await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({alg:'ECDH-ES',enc:'A256GCM',typ:'darkvault-response+jwe',cty:'application/json',kid:request.payload.requestId}).encrypt(reply);
  assert.deepEqual(await decryptResponse(compact,request,200),{items:[]});
  await assert.rejects(decryptResponse(compact,request,201));
});

test('Admin transport caches the key, retries unknown_key once and keeps sanitized error codes', async () => {
  const { build } = await import('esbuild');
  const { generateKeyPair, exportJWK } = await import('jose');
  const { outputFiles } = await build({ entryPoints: ['src/protocol.ts'], bundle: true, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], write: false });
  const { execute } = await import('data:text/javascript;base64,' + Buffer.from(outputFiles[0].text).toString('base64'));
  const pair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const serverKey = {
    protocolVersion: 1, serverId: '00000000-0000-4000-8000-000000000001', kid: '00000000-0000-4000-8000-000000000002',
    publicKey: await exportJWK(pair.publicKey), serverTime: new Date().toISOString(), notAfter: new Date(Date.now() + 300000).toISOString(),
    limits: { maxBodyBytes: 2 * 1024 * 1024, maxPlaintextBytes: 1536 * 1024 }
  };
  const json = (body, status, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
  const replies = [
    () => json({ error: { code: 'unknown_key' } }, 400),
    () => json({ error: { code: 'forbidden' } }, 403),
    () => json({ error: { code: 'rate_limited' } }, 429, { 'Retry-After': '2' }),
    () => json({ error: { code: 'Not<Safe>' } }, 500),
    () => new Response('', { status: 401 })
  ];
  let discovery = 0, posts = 0;
  const previous = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url === '/api/v1/crypto/key') { discovery++; return json(serverKey, 200); }
    assert.equal(options.headers['X-CSRF-Token'], 'csrf');
    return replies[posts++]();
  };
  try {
    await assert.rejects(execute('bucket.list', {}, 'csrf'), error => error.code === 'forbidden' && error.status === 403);
    assert.equal(discovery, 2, 'unknown_key refreshes the key once');
    await assert.rejects(execute('bucket.list', {}, 'csrf'), error => error.code === 'rate_limited' && error.retryAfterMs === 2000);
    await assert.rejects(execute('bucket.list', {}, 'csrf'), error => error.code === 'transport_error' && error.status === 500);
    await assert.rejects(execute('bucket.list', {}, 'csrf'), /Session expired/);
    assert.equal(discovery, 2, 'the refreshed key stays cached');
    assert.equal(posts, 5);
  } finally { globalThis.fetch = previous; }
});

test('Token maximum uses a UTC calendar year, including leap days', async () => {
  const { build } = await import('esbuild');
  const { outputFiles } = await build({ entryPoints: ['src/expiry.ts'], bundle: true, format: 'esm', write: false });
  const { nextYear } = await import('data:text/javascript;base64,' + Buffer.from(outputFiles[0].text).toString('base64'));
  for (const [start, expected] of [
    ['2028-02-29T13:45:12.123Z', '2029-02-28T13:45:12.123Z'],
    ['2027-03-01T10:20:00.000Z', '2028-03-01T10:20:00.000Z'],
    ['2026-12-31T23:59:00.000Z', '2027-12-31T23:59:00.000Z']
  ]) {
    const now = new Date(start);
    assert.equal(nextYear(now).toISOString(), expected);
    assert.equal(now.toISOString(), start);
  }
});
