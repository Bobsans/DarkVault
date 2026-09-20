export type SecretType = 'string' | 'number' | 'boolean' | 'null';
export type SecretScalar = string | number | boolean | null;
export interface Configuration { [key: string]: SecretScalar | Configuration }

export function encodeScalar(value: SecretScalar): { value: string; type: SecretType } {
    if (typeof value === 'string') return { value, type: 'string' };
    if (value === null) return { value: 'null', type: 'null' };
    if (typeof value === 'boolean') return { value: String(value), type: 'boolean' };
    if (typeof value === 'number' && Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)))
        return { value: JSON.stringify(value), type: 'number' };
    throw new TypeError('Secret values must be strings, finite interoperable numbers, booleans, or null.');
}
export function parseScalar(value: string, type: SecretType = 'string'): SecretScalar {
    if (type === 'string') return value;
    let parsed: unknown;
    try { parsed = JSON.parse(value); } catch { throw new TypeError('Invalid secret type or scalar value.'); }
    if ((type === 'null' && parsed === null) || (type === 'boolean' && typeof parsed === 'boolean') || (type === 'number' && typeof parsed === 'number')) {
        encodeScalar(parsed as SecretScalar); return parsed as SecretScalar;
    }
    throw new TypeError('Invalid secret type or scalar value.');
}
export function typedSecrets(snapshot: { secrets: Record<string, string>; types?: Record<string, SecretType> | null }): Record<string, SecretScalar> {
    const result: Record<string, SecretScalar> = Object.create(null);
    if (snapshot.types != null && (typeof snapshot.types !== 'object' || Array.isArray(snapshot.types))) throw new TypeError('Invalid secret type map.');
    if (snapshot.types && Object.keys(snapshot.types).some(key => !Object.hasOwn(snapshot.secrets, key))) throw new TypeError('Invalid secret type map.');
    for (const [key, value] of Object.entries(snapshot.secrets)) result[key] = parseScalar(value, snapshot.types && Object.hasOwn(snapshot.types, key) ? snapshot.types[key] : 'string');
    return result;
}
function pathParts(key: string): string[] {
    const parts: string[] = []; let part = ''; let escaped = false;
    for (const ch of key) {
        if (escaped) { if (ch !== ':' && ch !== '\\') throw new TypeError('Invalid configuration path escape.'); part += ch; escaped = false; }
        else if (ch === '\\') escaped = true;
        else if (ch === ':') { parts.push(part); part = ''; }
        else part += ch;
    }
    parts.push(part);
    if (escaped || parts.length > 16 || parts.some(p => !p)) throw new TypeError('Invalid configuration path.');
    return parts;
}
export function buildConfiguration(values: Record<string, SecretScalar>, nested = true): Configuration {
    const root: Configuration = Object.create(null);
    for (const [key, value] of Object.entries(values)) {
        encodeScalar(value);
        const parts = nested ? pathParts(key) : [key]; let parent = root;
        for (const part of parts.slice(0, -1)) {
            if (!Object.hasOwn(parent, part)) parent[part] = Object.create(null);
            const child = parent[part];
            if (child === null || typeof child !== 'object') throw new TypeError('Configuration paths conflict: ' + key);
            parent = child;
        }
        const leaf = parts[parts.length - 1];
        if (Object.hasOwn(parent, leaf)) throw new TypeError('Configuration paths conflict: ' + key);
        parent[leaf] = value;
    }
    return root;
}
// Emit only our object/scalar model. Quoted JSON strings are also YAML double-quoted strings.
export function formatConfiguration(value: Configuration, format: 'json' | 'yaml'): string {
    if (format === 'json') return JSON.stringify(value, null, 2) + '\n';
    function lines(object: Configuration, indent: string): string[] {
        return Object.entries(object).flatMap(([key, item]) => {
            const prefix = indent + JSON.stringify(key) + ':';
            return item !== null && typeof item === 'object'
                ? Object.keys(item).length ? [prefix, ...lines(item, indent + '  ')] : [prefix + ' {}']
                : [prefix + ' ' + JSON.stringify(item)];
        });
    }
    return (Object.keys(value).length ? lines(value, '').join('\n') : '{}') + '\n';
}
