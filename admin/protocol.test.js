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
