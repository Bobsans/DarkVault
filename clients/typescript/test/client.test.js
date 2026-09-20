import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CompactEncrypt, importJWK } from 'jose';
import { DarkVaultClient, DarkVaultError } from '../dist/index.js';
import { encryptRequest, decryptResponse, parseStrict, readBounded } from '../dist/protocol.js';

const token = 'dv1_' + 'A'.repeat(60);
test('Validate origin, token, revision, pagination and cancellation', async () => {
    for (const url of ['http://vault.example.com', 'https://user@vault.example.com', 'https://vault.example.com/path']) {
        assert.throws(() => new DarkVaultClient(url, token));
    }
    assert.throws(() => new DarkVaultClient('vault.example.com', 'invalid'));
    assert.throws(() => new DarkVaultClient('vault.example.com', token, { timeoutMs: 30_001 }));
    const client = new DarkVaultClient('vault.example.com', token, { fetch: () => { throw new Error('must not fetch'); } });
    assert.throws(() => client.updateSecret('qa', 'key', 'value', Number.MAX_SAFE_INTEGER + 1));
    assert.throws(() => client.listBuckets(null, 201));
    const controller = new AbortController(); controller.abort();
    await assert.rejects(client.getTokenInfo(controller.signal), { name: 'AbortError' });
});

test('Strict JSON, bounded responses and response binding', async () => {
    for (const value of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '['.repeat(17) + '0' + ']'.repeat(17)]) assert.throws(() => parseStrict(value));
    await assert.rejects(readBounded(new Response(new Uint8Array(2 * 1024 * 1024 + 1))));
    await assert.rejects(readBounded(new Response(new Uint8Array([255]))));
    const { generateKeyPair, exportJWK } = await import('jose');
    const key = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const request = await encryptRequest({ serverId: 'test', kid: 'key', publicKey: await exportJWK(key.publicKey) }, 'token.info', {}, 'data');
    const payload = { v: 1, requestId: request.payload.requestId, serverId: 'test', audience: 'data', operation: 'token.info', status: 200, data: { id: 'token' }, error: null };
    const reply = await importJWK(request.payload.replyKey, 'ECDH-ES');
    const encrypt = (body) => new CompactEncrypt(new TextEncoder().encode(JSON.stringify(body)))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', typ: 'darkvault-response+jwe', cty: 'application/json', kid: request.payload.requestId }).encrypt(reply);
    const body = await encrypt(payload);
    assert.deepEqual(await decryptResponse(body, request, 200), { id: 'token' });
    await assert.rejects(decryptResponse(body, request, 201));
    await assert.rejects(decryptResponse(await encrypt({ ...payload, audience: 'admin' }), request, 200));
    const parts = body.split('.'); parts[4] = 'AAAAAAAAAAAAAAAAAAAAAA';
    await assert.rejects(decryptResponse(parts.join('.'), request, 200));
    await assert.rejects(decryptResponse(await encrypt({ ...payload, status: 403, data: null, error: { code: 'forbidden', message: 'private text' } }), request, 403),
        error => error instanceof DarkVaultError && error.code === 'forbidden' && error.status === 403 && !error.message.includes('private text'));
});

test('Transport rejects plaintext errors without sending tokens to discovery', async () => {
    const client = new DarkVaultClient('vault.example.com', token, { fetch: async (url, options) => {
        assert.equal(url, 'https://vault.example.com/api/v1/crypto/key');
        assert.equal(options.redirect, 'error');
        assert.equal(options.credentials, 'omit');
        assert.equal(options.headers, undefined);
        return new Response('private text', { status: 503 });
    } });
    await assert.rejects(client.getTokenInfo(), error => error instanceof DarkVaultError && error.code === 'key_unavailable' && !error.message.includes('private text'));
});

test('All SDK operations against the .NET HTTPS server', { skip: !process.env.DARKVAULT_ACCEPTANCE }, async () => {
    const descriptor = JSON.parse(await readFile(process.env.DARKVAULT_ACCEPTANCE, 'utf8'));
    const client = new DarkVaultClient(descriptor.url, await readFile(descriptor.tokenFile, 'utf8'));
    assert.ok((await client.getTokenInfo()).id);
    const name = 'typescript-sdk-live';
    let bucket = await client.addBucket(name, 'test');
    try {
        assert.equal((await client.getBucket(name)).id, bucket.id);
        bucket = await client.updateBucket(name, 'updated', bucket.revision);
        assert.equal(bucket.description, 'updated');
        let page = await client.listBuckets(null, 1);
        assert.equal(page.items.length, 1); assert.ok(page.nextCursor);
        assert.equal((await client.listBuckets(page.nextCursor, 1)).items.length, 1);
        let secret = await client.addSecret(name, 'first', '秘密\nvalue');
        assert.equal((await client.readSecret(name, 'first')).value, '秘密\nvalue');
        const updated = await client.updateSecret(name, 'first', 'updated', secret.revision);
        await assert.rejects(client.deleteSecret(name, 'first', secret.revision), error => error instanceof DarkVaultError && error.status === 409 && !!error.requestId);
        secret = await client.setSecret(name, 'first', 'set', updated.revision);
        await client.setSecret(name, 'second', '');
        page = await client.listSecrets(name, null, 1);
        assert.equal(page.items.length, 1); assert.ok(page.nextCursor);
        assert.equal((await client.listSecrets(name, page.nextCursor, 1)).items.length, 1);
        assert.deepEqual(await client.readBucket(name), { first: 'set', second: '' });
        await client.deleteSecret(name, 'first', secret.revision);
        const snapshot = await client.readBucketSnapshot(name);
        assert.equal(snapshot.bucketId, bucket.id); assert.deepEqual(snapshot.secrets, { second: '' });
        await client.deleteBucket(name, snapshot.revision, true);
    } finally {
        try { const current = await client.getBucket(name); await client.deleteBucket(name, current.revision, true); }
        catch (error) { if (!(error instanceof DarkVaultError) || error.status !== 404) throw error; }
    }
});
