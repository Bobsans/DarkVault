import { encryptRequest, decryptResponse, parseStrict, readBounded } from './protocol.js';
import { DarkVaultError } from './errors.js';
import type { JWK } from 'jose';
import { encodeScalar, parseScalar, typedSecrets, buildConfiguration } from './configuration.js';
import type { SecretType, SecretScalar, Configuration } from './configuration.js';
export * from './configuration.js';
export { DarkVaultError } from './errors.js';

export interface Bucket {
    id: string; name: string; description: string; revision: number; createdAt: string; updatedAt: string;
}
export interface SecretMetadata {
    id: string; bucketId: string; key: string; revision: number; createdAt: string; updatedAt: string; type: SecretType;
}
export interface Secret extends SecretMetadata { value: string }
export interface BucketSnapshot { bucketId: string; revision: number; secrets: Record<string, string>; types: Record<string, SecretType> }
export interface Page<T> { items: T[]; nextCursor: string | null }
export interface TokenInfo {
    id: string; name: string; scopes: string[]; bucketIds: string[]; allBuckets: boolean;
    creatableBucketNames: string[]; expiresAt: string | null;
}
export interface ClientOptions { timeoutMs?: number; fetch?: typeof globalThis.fetch }
type ServerKey = { protocolVersion: number; serverId: string; serverTime: string; kid: string; publicKey: JWK; notAfter: string; limits: { maxBodyBytes: number; maxPlaintextBytes: number } };

function retryAfterMs(value: string | null): number {
    if (!value) return 0;
    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1000);
    const date = Date.parse(value);
    return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
}

function revision(value: number): number {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Revision must be a nonnegative safe integer.');
    return value;
}
function pageLimit(value: number): number {
    if (!Number.isInteger(value) || value < 1 || value > 200) throw new TypeError('Limit must be between 1 and 200.');
    return value;
}

function validateData(operation: string, data: unknown): void {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new DarkVaultError("invalid_response");
    const object = data as Record<string, unknown>;
    if (operation.endsWith(".delete")) { if (object.deleted !== true) throw new DarkVaultError("invalid_response"); return; }
    if (operation.endsWith(".list")) {
        if (!Array.isArray(object.items) || !("nextCursor" in object) || (object.nextCursor !== null && typeof object.nextCursor !== "string")) throw new DarkVaultError("invalid_response");
        // Every element must satisfy the single-record schema; a missing field must not reach the caller as undefined.
        for (const item of object.items) validateRecord(operation, item);
        return;
    }
    validateRecord(operation, data);
}
function validateRecord(operation: string, data: unknown): void {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new DarkVaultError("invalid_response");
    const object = data as Record<string, unknown>;
    const required = (...fields: string[]) => { if (fields.some(field => !(field in object) || object[field] === null || object[field] === undefined)) throw new DarkVaultError("invalid_response"); };
    const stringMap = (value: unknown) => { if (!value || typeof value !== "object" || Array.isArray(value) || Object.values(value).some(entry => typeof entry !== "string")) throw new DarkVaultError("invalid_response"); };
    if (operation === "bucket.read") { required("bucketId", "revision", "secrets", "types"); stringMap(object.secrets); stringMap(object.types); return; }
    if (operation === "token.info") { required("id", "name", "scopes", "bucketIds", "allBuckets", "creatableBucketNames"); if (!("expiresAt" in object)) throw new DarkVaultError("invalid_response"); return; }
    if (operation.startsWith("secret.")) { required("id", "bucketId", "key", "revision", "createdAt", "updatedAt", "type"); if (operation === "secret.read") required("value"); return; }
    required("id", "name", "description", "revision", "createdAt", "updatedAt");
}

export class DarkVaultClient {
    readonly #origin: string;
    readonly #token: string;
    readonly #fetch: typeof globalThis.fetch;
    readonly #timeout: number;
    #serverKey?: ServerKey;
    #serverKeyUntil = 0;

    #defaultBucket?: string;
    get defaultBucket(): string | undefined { return this.#defaultBucket; }

    static fromUrl(connectionString: string, options: ClientOptions = {}): DarkVaultClient {
        const match = typeof connectionString === 'string'
            ? /^https:\/\/(dv1_[A-Za-z0-9_-]{60})@([^/?#@\s\\]+)\/([a-z0-9][a-z0-9_-]{0,62})$/.exec(connectionString) : null;
        if (!match || match[0] !== connectionString) throw new TypeError('Invalid DarkVault connection string.');
        let origin: URL;
        try { origin = new URL('https://' + match[2]); }
        catch { throw new TypeError('Invalid DarkVault connection string.'); }
        if (origin.port === '0') throw new TypeError('Invalid DarkVault connection string.');
        const client = new DarkVaultClient(origin.origin, match[1], options);
        client.#defaultBucket = match[3];
        return client;
    }

    private resolveBucket(bucket?: string): string {
        const resolved = bucket ?? this.#defaultBucket;
        if (resolved === undefined) throw new TypeError('Specify a bucket or use a connection string containing one.');
        return resolved;
    }

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
        let keyRetry = false;
        while (true) {
            let key = this.#serverKey;
            const now = Date.now();
            if (!key || this.#serverKeyUntil <= now || Date.parse(key.notAfter) <= now) {
                const discovery = await fetchChecked('/api/v1/crypto/key', requestOptions);
                if (!discovery.ok) { await discovery.body?.cancel(); throw new DarkVaultError('key_unavailable', discovery.status); }
                const candidate = parseStrict(await readBounded(discovery)) as ServerKey;
                const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                if (!candidate || Object.keys(candidate).sort().join(",") !== "kid,limits,notAfter,protocolVersion,publicKey,serverId,serverTime" || candidate.protocolVersion !== 1 || typeof candidate.serverId !== "string" || typeof candidate.serverTime !== "string" || typeof candidate.kid !== "string" || typeof candidate.notAfter !== "string" || !uuid.test(candidate.serverId) || !uuid.test(candidate.kid) || !Number.isFinite(Date.parse(candidate.serverTime)) || !Number.isFinite(Date.parse(candidate.notAfter)) || Date.parse(candidate.notAfter) <= Date.now() ||
            !candidate.limits || !Number.isSafeInteger(candidate.limits.maxBodyBytes) || candidate.limits.maxBodyBytes < 1 || candidate.limits.maxBodyBytes > 2 * 1024 * 1024 || !Number.isSafeInteger(candidate.limits.maxPlaintextBytes) || candidate.limits.maxPlaintextBytes < 1 || candidate.limits.maxPlaintextBytes > 1536 * 1024 ||
            candidate.publicKey?.kty !== 'EC' || candidate.publicKey?.crv !== 'P-256' ||
            Object.keys(candidate.publicKey).sort().join(',') !== 'crv,kty,x,y') throw new DarkVaultError('invalid_server_key');
                key = candidate;
                this.#serverKey = key;
                this.#serverKeyUntil = Math.min(Date.now() + 300_000, Date.parse(key.notAfter));
            }
            const request = await encryptRequest(key, operation, parameters, 'data');
            deadline.throwIfAborted();
            const response = await fetchChecked('/api/v1/execute', {
                ...requestOptions, method: 'POST', body: request.body,
                headers: { 'Authorization': `Bearer ${this.#token}`, 'Content-Type': 'application/jose', 'Accept': 'application/jose' }
            });
            if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose') {
                const body = await readBounded(response);
                let code = 'transport_error';
                try {
                    const candidate = parseStrict(body) as { error?: { code?: unknown } };
                    if (typeof candidate?.error?.code === 'string' && /^[a-z_]{1,64}$/.test(candidate.error.code)) code = candidate.error.code;
                } catch { /* keep safe generic code */ }
                const retryAfter = retryAfterMs(response.headers.get('Retry-After'));
                if (code === 'unknown_key' && !keyRetry) {
                    this.#serverKey = undefined; this.#serverKeyUntil = 0; keyRetry = true; continue;
                }
                if (response.ok) throw new DarkVaultError('unencrypted_response', response.status, request.payload.requestId, retryAfter);
                throw new DarkVaultError(code, response.status, request.payload.requestId, retryAfter);
            }
        let data: unknown;
            try { data = await decryptResponse(await readBounded(response), request, response.status); }
            catch (error) {
                deadline.throwIfAborted();
                if (error instanceof DarkVaultError) throw error;
                throw new DarkVaultError('invalid_response', response.status, request.payload.requestId);
            }
            deadline.throwIfAborted();
            validateData(operation, data);
            return data as T;
        }
    }

    addBucket(name: string, description = '', signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.create', { name, description }, signal); }
    getBucket(bucket: string, signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.get', { bucket }, signal); }
    listBuckets(cursor: string | null = null, limit = 100, signal?: AbortSignal): Promise<Page<Bucket>> { return this.execute('bucket.list', { cursor, limit: pageLimit(limit) }, signal); }
    readBucketSnapshot(bucket?: string, signal?: AbortSignal): Promise<BucketSnapshot> { return this.execute('bucket.read', { bucket: this.resolveBucket(bucket) }, signal); }
    async readBucket(bucket?: string, signal?: AbortSignal): Promise<Record<string, string>> { return (await this.readBucketSnapshot(bucket, signal)).secrets; }
    async readTypedBucket(bucket?: string, signal?: AbortSignal): Promise<Record<string, SecretScalar>> { return typedSecrets(await this.readBucketSnapshot(bucket, signal)); }
    async readConfiguration(bucket?: string, nested = true, signal?: AbortSignal): Promise<Configuration> { return buildConfiguration(await this.readTypedBucket(bucket, signal), nested); }
    updateBucket(bucket: string, description: string, expectedRevision: number, signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.update', { bucket, description, expectedRevision: revision(expectedRevision) }, signal); }
    renameBucket(bucket: string, name: string, expectedRevision: number, signal?: AbortSignal): Promise<Bucket> { return this.execute('bucket.update', { bucket, name, expectedRevision: revision(expectedRevision) }, signal); }
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

/** Load one nested configuration snapshot; an omitted URL reads DARKVAULT_URL in Node.js. */
export async function loadConfiguration(url?: string, options: ClientOptions = {}, signal?: AbortSignal): Promise<Configuration> {
    if (url === undefined) {
        url = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.DARKVAULT_URL;
        if (typeof url !== 'string' || !url.trim()) {
            throw new TypeError('Set DARKVAULT_URL in the process environment or pass a URL explicitly (required in browsers).');
        }
    }
    return DarkVaultClient.fromUrl(url, options).readConfiguration(undefined, true, signal);
}
