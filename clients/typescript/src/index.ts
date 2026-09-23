import { encryptRequest, decryptResponse, parseStrict, readBounded, validateServerKey, retryAfterMs } from './protocol.js';
import type { ServerKey } from './protocol.js';
import { DarkVaultError } from './errors.js';
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
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new DarkVaultError('invalid_response');
    const object = data as Record<string, unknown>;
    const strings = (...fields: string[]) => fields.every(field => typeof object[field] === 'string');
    const revision = (field: string) => Number.isSafeInteger(object[field]) && (object[field] as number) >= 0;
    const stringArray = (field: string) => Array.isArray(object[field]) && object[field].every(item => typeof item === 'string');
    const date = (field: string) => typeof object[field] === 'string' && Number.isFinite(Date.parse(object[field] as string));
    if (operation === 'bucket.read') {
        const types = object.types;
        if (typeof object.bucketId !== 'string' || !revision('revision') || !object.secrets || typeof object.secrets !== 'object' || Array.isArray(object.secrets) || Object.values(object.secrets).some(value => typeof value !== 'string') || !types || typeof types !== 'object' || Array.isArray(types) || Object.values(types).some(value => !['string', 'number', 'boolean', 'null'].includes(String(value)))) throw new DarkVaultError('invalid_response');
        return;
    }
    if (operation === 'token.info') {
        if (!strings('id', 'name') || !stringArray('scopes') || !stringArray('bucketIds') || !stringArray('creatableBucketNames') || typeof object.allBuckets !== 'boolean' || !('expiresAt' in object) || !(object.expiresAt === null || date('expiresAt'))) throw new DarkVaultError('invalid_response');
        return;
    }
    if (operation.startsWith('secret.')) {
        if (!strings('id', 'bucketId', 'key', 'type') || !revision('revision') || !date('createdAt') || !date('updatedAt') || !['string', 'number', 'boolean', 'null'].includes(String(object.type)) || (operation === 'secret.read' && typeof object.value !== 'string')) throw new DarkVaultError('invalid_response');
        return;
    }
    if (!strings('id', 'name', 'description') || !revision('revision') || !date('createdAt') || !date('updatedAt')) throw new DarkVaultError('invalid_response');
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
        const read = operation.endsWith('.read') || operation.endsWith('.get') || operation.endsWith('.list') || operation === 'token.info';
        let activeRequestId: string | undefined;
        const fetchChecked = async (path: string, options: RequestInit): Promise<Response> => {
            deadline.throwIfAborted();
            let response: Response;
            try { response = await this.#fetch(this.#origin + path, options); }
            catch (cause) {
                if (path.endsWith('/execute')) throw new DarkVaultError(read ? (deadline.aborted ? 'timeout' : 'unavailable') : 'request_outcome_unknown', 0, activeRequestId, 0, cause);
                if (deadline.aborted) deadline.throwIfAborted();
                throw new DarkVaultError('server_unavailable', 0, undefined, 0, cause);
            }
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
                const candidate = validateServerKey(parseStrict(await readBounded(discovery)));
                key = candidate;
                this.#serverKey = key;
                this.#serverKeyUntil = Math.min(Date.now() + 300_000, Date.parse(key.notAfter));
            }
            const request = await encryptRequest(key, operation, parameters, 'data');
            activeRequestId = request.payload.requestId;
            deadline.throwIfAborted();
            const response = await fetchChecked('/api/v1/execute', {
                ...requestOptions, method: 'POST', body: request.body,
                headers: { 'Authorization': `Bearer ${this.#token}`, 'Content-Type': 'application/jose', 'Accept': 'application/jose' }
            });
            let body: string;
            try { body = await readBounded(response); }
            catch (cause) { throw new DarkVaultError(read ? 'timeout' : 'request_outcome_unknown', response.status, request.payload.requestId, 0, cause); }
            if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose') {
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
            try { data = await decryptResponse(body, request, response.status); }
            catch (cause) {
                if (deadline.aborted) throw new DarkVaultError(read ? 'timeout' : 'request_outcome_unknown', response.status, request.payload.requestId, 0, cause);
                if (cause instanceof DarkVaultError) throw cause;
                throw new DarkVaultError('invalid_response', response.status, request.payload.requestId, 0, cause);
            }
            if (deadline.aborted) throw new DarkVaultError(read ? 'timeout' : 'request_outcome_unknown', response.status, request.payload.requestId);
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
