export class DarkVaultError extends Error {
    readonly code: string;
    constructor(code: unknown, readonly status = 0, readonly requestId?: string, readonly retryAfterMs = 0, cause?: unknown) {
        const safeCode = typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : 'invalid_error';
        super(`DarkVault request failed (${safeCode}).`, cause === undefined ? undefined : { cause });
        this.name = 'DarkVaultError';
        this.code = safeCode;
    }
}
