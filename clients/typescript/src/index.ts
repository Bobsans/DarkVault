import { encryptRequest, decryptResponse, parseStrict, readBounded } from './protocol.js';
import { DarkVaultError } from './errors.js';
import { encodeScalar, parseScalar, typedSecrets, buildConfiguration } from './configuration.js';
import type { SecretType, SecretScalar, Configuration } from './configuration.js';
export * from './configuration.js';
export { DarkVaultError } from './errors.js';

export interface Bucket {
    id: string; name: string; description: string; revision: number; createdAt: string; updatedAt: string;
}
export interface SecretMetadata {
    id: string; bucketId: string; key: string; revision: number; createdAt: string; updatedAt: string; type?: SecretType;
}
export interface Secret extends SecretMetadata { value: string }
export interface BucketSnapshot { bucketId: string; revision: number; secrets: Record<string, string>; types?: Record<string, SecretType> }
export interface Page<T> { items: T[]; nextCursor: string | null }
export interface TokenInfo {
    id: string; name: string; scopes: string[]; bucketIds: string[]; allBuckets: boolean;
    creatableBucketNames: string[]; expiresAt: string | null;
}
export interface ClientOptions { timeoutMs?: number; fetch?: typeof globalThis.fetch }

function revision(value: number): number {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Revision must be a nonnegative safe integer.');
    return value;
}
function pageLimit(value: number): number {
    if (!Number.isInteger(value) || value < 1 || value > 200) throw new TypeError('Limit must be between 1 and 200.');
    return value;
}

export class DarkVaultClient {
    readonly #origin: string;
    readonly #token: string;
    readonly #fetch: typeof globalThis.fetch;
    readonly #timeout: number;

    constructor(server: string, token: string, options: ClientOptions = {}) {
        const url = new URL(server.includes('://') ? server : `https://${server}`);
        if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
            throw new TypeError('Use an HTTPS origin without credentials, path, query or fragment.');
        }
        if (!/^dv1_[A-Za-z0-9_-]{60}$/.test(token)) throw new TypeError('Invalid token format.');
        this.#origin = url.origin;
        this.#token = token;
        this.#fetch = options.fetch ?? globalThis.fetch;
        this.#timeout = options.timeoutMs ?? 30_000;
        if (!Number.isInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 30_000) throw new TypeError('Timeout must be between 1 and 30000 ms.');
    }

    async execute<T = unknown>(operation: string, parameters: object, signal?: AbortSignal): Promise<T> {
        const timeout = AbortSignal.timeout(this.#timeout);
        const deadline = signal ? AbortSignal.any([signal, timeout]) : timeout;
        const requestOptions: RequestInit = { signal: deadline, redirect: 'error', cache: 'no-store', credentials: 'omit' };
        const fetchChecked = async (path: string, options: RequestInit): Promise<Response> => {
            deadline.throwIfAborted();
            let response: Response;
            try { response = await this.#fetch(this.#origin + path, options); }
            catch { deadline.throwIfAborted(); throw new DarkVaultError(path.endsWith('/execute') ? 'request_outcome_unknown' : 'server_unavailable'); }
            if (response.redirected || (response.url && new URL(response.url).origin !== this.#origin)) {
                await response.body?.cancel();
                throw new DarkVaultError('redirect_rejected', response.status);
            }
            return response;
        };
        const discovery = await fetchChecked('/api/v1/crypto/key', requestOptions);
        if (!discovery.ok) { await discovery.body?.cancel(); throw new DarkVaultError('key_unavailable', discovery.status); }
        const key = parseStrict(await readBounded(discovery));
        const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!key || key.protocolVersion !== 1 || typeof key.serverId !== 'string' || typeof key.kid !== 'string' || typeof key.notAfter !== 'string' || !uuid.test(key.serverId) || !uuid.test(key.kid) ||
            !Number.isFinite(Date.parse(key.notAfter)) || Date.parse(key.notAfter) <= Date.now() ||
            key.publicKey?.kty !== 'EC' || key.publicKey?.crv !== 'P-256' ||
            Object.keys(key.publicKey).sort().join(',') !== 'crv,kty,x,y') throw new DarkVaultError('invalid_server_key');
        const request = await encryptRequest(key, operation, parameters, 'data');
        deadline.throwIfAborted();
        const response = await fetchChecked('/api/v1/execute', {
            ...requestOptions, method: 'POST', body: request.body,
            headers: { 'Authorization': `Bearer ${this.#token}`, 'Content-Type': 'application/jose', 'Accept': 'application/jose' }
        });
        if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose') {
            await response.body?.cancel();
            throw new DarkVaultError('transport_error', response.status, request.payload.requestId);
        }
        let data: unknown;
        try { data = await decryptResponse(await readBounded(response), request, response.status); }
        catch (error) {
            deadline.throwIfAborted();
            if (error instanceof DarkVaultError) throw error;
            throw new DarkVaultError('invalid_response', response.status, request.payload.requestId);
        }
        deadline.throwIfAborted();
        return data as T;
    }

    addBucket(name: string, description = '', signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.create', { name, description }, signal); }
    getBucket(bucket: string, signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.get', { bucket }, signal); }
    listBuckets(cursor: string | null = null, limit = 100, signal?: AbortSignal): Promise<Page<Bucket>> { return this.execute('bucket.list', { cursor, limit: pageLimit(limit) }, signal); }
    readBucketSnapshot(bucket: string, signal?: AbortSignal): Promise<BucketSnapshot> { return this.execute('bucket.read', { bucket }, signal); }
    async readBucket(bucket: string, signal?: AbortSignal): Promise<Record<string, string>> { return (await this.readBucketSnapshot(bucket, signal)).secrets; }
    async readTypedBucket(bucket: string, signal?: AbortSignal): Promise<Record<string, SecretScalar>> { return typedSecrets(await this.readBucketSnapshot(bucket, signal)); }
    async readConfiguration(bucket: string, nested = true, signal?: AbortSignal): Promise<Configuration> { return buildConfiguration(await this.readTypedBucket(bucket, signal), nested); }
    updateBucket(bucket: string, description: string, expectedRevision: number, signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.update', { bucket, description, expectedRevision: revision(expectedRevision) }, signal); }
    async deleteBucket(bucket: string, expectedRevision: number, recursive = false, signal?: AbortSignal): Promise<void> { await this.execute('bucket.delete', { bucket, expectedRevision: revision(expectedRevision), recursive }, signal); }
    addSecret(bucket: string, key: string, value: SecretScalar, signal?: AbortSignal): Promise<SecretMetadata> { return this.execute('secret.create', { bucket, key, ...encodeScalar(value) }, signal); }
    readSecret(bucket: string, key: string, signal?: AbortSignal): Promise<Secret> { return this.execute('secret.read', { bucket, key }, signal); }
    async readTypedSecret(bucket: string, key: string, signal?: AbortSignal): Promise<Omit<Secret, 'value'> & { value: SecretScalar }> { const secret = await this.readSecret(bucket, key, signal); return { ...secret, value: parseScalar(secret.value, secret.type) }; }
    listSecrets(bucket: string, cursor: string | null = null, limit = 100, signal?: AbortSignal): Promise<Page<SecretMetadata>> { return this.execute('secret.list', { bucket, cursor, limit: pageLimit(limit) }, signal); }
    updateSecret(bucket: string, key: string, value: SecretScalar, expectedRevision: number, signal?: AbortSignal): Promise<SecretMetadata> { return this.execute('secret.update', { bucket, key, ...encodeScalar(value), expectedRevision: revision(expectedRevision) }, signal); }
    setSecret(bucket: string, key: string, value: SecretScalar, expectedRevision = 0, signal?: AbortSignal): Promise<SecretMetadata> { return this.execute('secret.set', { bucket, key, ...encodeScalar(value), expectedRevision: revision(expectedRevision) }, signal); }
    async deleteSecret(bucket: string, key: string, expectedRevision: number, signal?: AbortSignal): Promise<void> { await this.execute('secret.delete', { bucket, key, expectedRevision: revision(expectedRevision) }, signal); }
    getTokenInfo(signal?: AbortSignal): Promise<TokenInfo> { return this.execute('token.info', {}, signal); }
}
