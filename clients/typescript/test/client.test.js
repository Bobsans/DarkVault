import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CompactEncrypt, importJWK } from 'jose';
import { DarkVaultClient, DarkVaultError, loadConfiguration, parseScalar, encodeScalar, buildConfiguration, formatConfiguration } from '../dist/index.js';
import { encryptRequest, decryptResponse, parseStrict, readBounded } from '../dist/protocol.js';

const token = 'dv1_' + 'A'.repeat(60);
test('Typed scalars and configuration export preserve types and reject ambiguous paths', () => {
    assert.equal(parseScalar('00123'), '00123'); assert.equal(parseScalar('false', 'boolean'), false); assert.equal(parseScalar('null', 'null'), null);
    for (const value of [NaN, Infinity, 9007199254740992, {}, []]) assert.throws(() => encodeScalar(value));
    for (const [value, type] of [['01','number'], ['true','number'], ['1','boolean'], ['','null']]) assert.throws(() => parseScalar(value,type));
    const tree = buildConfiguration({ 'Redis:Port': 6379, 'Redis:Enabled': false, 'Literal\\:Key': '00123', '__proto__:safe': true, 'Empty': null, 'Years:2026': 'x' });
    assert.equal(tree.Redis.Port, 6379); assert.equal(tree.Redis.Enabled, false); assert.equal(tree['Literal:Key'], '00123');
    assert.equal(tree.__proto__.safe, true); assert.equal({}.safe, undefined); assert.equal(tree.Years['2026'], 'x');
    const yaml = formatConfiguration(tree, 'yaml'); assert.match(yaml, /"Port": 6379/); assert.match(yaml, /"Enabled": false/); assert.match(yaml, /"Literal:Key": "00123"/); assert.match(yaml, /"Empty": null/);
    for (const values of [{ A: 'x', 'A:B': 1 }, { 'A:B': 1, A: null }, { 'A::B': true }, { 'A\\x': true }]) assert.throws(() => buildConfiguration(values));
    assert.equal(buildConfiguration({ 'A:B': 1, A: 2 }, false)['A:B'], 1);
});
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

test('Caches server keys and preserves plaintext error metadata', async () => {
    const { generateKeyPair, exportJWK } = await import('jose');
    const pair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const serverKey = {
        protocolVersion: 1,
        serverId: '00000000-0000-4000-8000-000000000001',
        kid: '00000000-0000-4000-8000-000000000002',
        publicKey: await exportJWK(pair.publicKey),
        notAfter: new Date(Date.now() + 300000).toISOString()
    };
    let discovery = 0; let posts = 0;
    const client = new DarkVaultClient('vault.example.com', token, { fetch: async url => {
        if (url.endsWith('/crypto/key')) { discovery++; return new Response(JSON.stringify(serverKey), { status: 200, headers: { 'Content-Type': 'application/json' } }); }
        posts++;
        const code = posts === 1 ? 'rate_limited' : 'unauthorized';
        return new Response(JSON.stringify({ error: { code } }), { status: posts === 1 ? 429 : 401, headers: { 'Content-Type': 'application/json', 'Retry-After': '7' } });
    } });
    await assert.rejects(client.getTokenInfo(), error => error instanceof DarkVaultError && error.code === 'rate_limited' && error.retryAfterMs === 7000);
    await assert.rejects(client.getTokenInfo(), error => error instanceof DarkVaultError && error.code === 'unauthorized');
    assert.equal(discovery, 1); assert.equal(posts, 2);

    let refreshDiscovery = 0; let refreshPosts = 0;
    const rotating = new DarkVaultClient('vault.example.com', token, { fetch: async url => {
        if (url.endsWith('/crypto/key')) { refreshDiscovery++; return new Response(JSON.stringify(serverKey), { status: 200, headers: { 'Content-Type': 'application/json' } }); }
        refreshPosts++;
        const code = refreshPosts === 1 ? 'unknown_key' : 'unauthorized';
        return new Response(JSON.stringify({ error: { code } }), { status: refreshPosts === 1 ? 400 : 401, headers: { 'Content-Type': 'application/json' } });
    } });
    await assert.rejects(rotating.getTokenInfo(), error => error instanceof DarkVaultError && error.code === 'unauthorized');
    assert.equal(refreshDiscovery, 2); assert.equal(refreshPosts, 2);
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
        const renamed = await client.renameBucket(name, name + '-renamed', bucket.revision);
        assert.equal(renamed.id, bucket.id);
        assert.equal((await client.getBucket(name + '-renamed')).description, 'updated');
        bucket = await client.renameBucket(name + '-renamed', name, renamed.revision);
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
        const connectionClient = DarkVaultClient.fromUrl(descriptor.url.replace('https://', 'https://' + await readFile(descriptor.tokenFile, 'utf8') + '@') + '/' + name);
        assert.deepEqual(await connectionClient.readBucket(), { first: 'set', second: '' });
        await client.deleteSecret(name, 'first', secret.revision);
        const snapshot = await client.readBucketSnapshot(name);
        assert.equal(snapshot.bucketId, bucket.id); assert.deepEqual(snapshot.secrets, { second: '' });
        await client.addSecret(name, 'Redis:Port', 6379); await client.addSecret(name, 'Redis:Enabled', false); await client.addSecret(name, 'Redis:Optional', null);
        assert.equal((await client.readSecret(name, 'Redis:Port')).type, 'number');
        assert.equal((await client.readTypedSecret(name, 'Redis:Enabled')).value, false);
        assert.equal((await client.readBucket(name))['Redis:Optional'], 'null');
        assert.equal((await client.readConfiguration(name)).Redis.Port, 6379);
        const config = await loadConfiguration(descriptor.url.replace('https://', 'https://' + await readFile(descriptor.tokenFile, 'utf8') + '@') + '/' + name); assert.equal(config.Redis.Port, 6379); assert.equal(config.Redis.Optional, null);
        const previousUrl = process.env.DARKVAULT_URL;
        try {
            process.env.DARKVAULT_URL = descriptor.url.replace('https://', 'https://' + await readFile(descriptor.tokenFile, 'utf8') + '@') + '/' + name;
            assert.deepEqual(await loadConfiguration(), config);
        } finally {
            if (previousUrl === undefined) delete process.env.DARKVAULT_URL;
            else process.env.DARKVAULT_URL = previousUrl;
        }
        const flag = await client.readSecret(name, 'Redis:Enabled'); await client.updateSecret(name, flag.key, true, flag.revision);
        assert.equal((await client.readTypedBucket(name))[flag.key], true);
        await client.deleteBucket(name, (await client.getBucket(name)).revision, true);
    } finally {
        try { const current = await client.getBucket(name); await client.deleteBucket(name, current.revision, true); }
        catch (error) { if (!(error instanceof DarkVaultError) || error.status !== 404) throw error; }
    }
});

test('Connection strings resolve the default bucket and isolate credentials', async () => {
    for (const host of ['vault.example.com', 'localhost:8443', '[::1]:8443']) {
        const client = DarkVaultClient.fromUrl('https://' + token + '@' + host + '/qa', {
            fetch: async url => {
                assert.equal(url, 'https://' + host + '/api/v1/crypto/key');
                return new Response('', { status: 400 });
            }
        });
        assert.equal(client.defaultBucket, 'qa');
        await assert.rejects(client.readBucket(), DarkVaultError);
        client.execute = async (op, parameters) => { assert.equal(op, 'bucket.read'); return { secrets: { bucket: parameters.bucket } }; };
        assert.deepEqual(await client.readBucket(), { bucket: 'qa' });
        assert.deepEqual(await client.readBucket('other'), { bucket: 'other' });
    }
    for (const raw of ["http://{token}@vault.example.com/qa", "https://vault.example.com/qa", "https://{token}:password@vault.example.com/qa", "https://{token}@vault.example.com", "https://{token}@vault.example.com/", "https://{token}@vault.example.com/qa/", "https://{token}@vault.example.com/a/../qa", "https://{token}@vault.example.com/qa?x=1", "https://{token}@vault.example.com/qa#x", "https://{token}@vault.example.com/qa\n", "https://{token}@vault.example.com:0/qa", "https://{token}@vault.example.com:65536/qa", "https://{token}@[bad/qa", "https://{token}@/qa", "https://{token}@vault.example.com/UPPER", "https://{token}@vault.example.com/%71a", "https://bad@vault.example.com/qa"]) {
        assert.throws(() => DarkVaultClient.fromUrl(raw.replace('{token}', token)),
            error => error instanceof TypeError && !String(error).includes(token) && !JSON.stringify(error).includes(token));
    }
    await assert.rejects(new DarkVaultClient('vault.example.com', token).readBucket(), TypeError);
});

test('loadConfiguration forwards transport options and cancellation', async () => {
    const controller = new AbortController(); controller.abort();
    const url = 'https://' + token + '@vault.example.com/qa';
    await assert.rejects(loadConfiguration(url, { fetch: () => { throw new Error('must not fetch'); } }, controller.signal), { name: 'AbortError' });
    let calls = 0;
    await assert.rejects(loadConfiguration(url, { fetch: async origin => {
        calls++;
        assert.equal(origin, 'https://vault.example.com/api/v1/crypto/key');
        return new Response('', { status: 403 });
    } }), DarkVaultError);
    assert.equal(calls, 1);
});

test('loadConfiguration reads the environment only when URL is omitted', async () => {
    const previous = process.env.DARKVAULT_URL;
    const url = 'https://' + token + '@vault.example.com/qa';
    const options = { fetch: async origin => {
        assert.equal(origin, 'https://vault.example.com/api/v1/crypto/key');
        return new Response('', { status: 403 });
    } };
    try {
        delete process.env.DARKVAULT_URL;
        await assert.rejects(loadConfiguration(), /DARKVAULT_URL/);
        for (const missing of ['', ' \t ']) {
            process.env.DARKVAULT_URL = missing;
            await assert.rejects(loadConfiguration(), /DARKVAULT_URL/);
        }
        process.env.DARKVAULT_URL = url;
        await assert.rejects(loadConfiguration(undefined, options), DarkVaultError);
        await assert.rejects(loadConfiguration(''), TypeError);
        const controller = new AbortController(); controller.abort();
        await assert.rejects(loadConfiguration(undefined, options, controller.signal), { name: 'AbortError' });
        process.env.DARKVAULT_URL = 'invalid';
        await assert.rejects(loadConfiguration(url, options), DarkVaultError);
    } finally {
        if (previous === undefined) delete process.env.DARKVAULT_URL;
        else process.env.DARKVAULT_URL = previous;
    }
    const originalProcess = globalThis.process;
    try {
        globalThis.process = undefined;
        await assert.rejects(loadConfiguration(), /pass a URL explicitly/);
        await assert.rejects(loadConfiguration(url, options), DarkVaultError);
    } finally {
        globalThis.process = originalProcess;
    }
});
