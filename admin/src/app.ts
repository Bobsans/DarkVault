import { execute } from './protocol.js';
import { setupExpiry } from './expiry.js';
import { buildConfiguration, formatConfiguration, typedSecrets, encodeScalar, parseScalar } from '@darkvault/client';
import type { Bucket, Secret, SecretMetadata, Page, TokenInfo, BucketSnapshot, SecretType } from '@darkvault/client';

interface TokenRecord { info: TokenInfo; revokedAt: string | null; lastUsedAt: string | null }
interface AuditEntry {
    time: string; principal: string; operation: string; result: string; requestId: string;
    kind?: string; principalName?: string; principalType?: string; sourceIp?: string; peerIp?: string;
    method?: string; path?: string; statusCode?: number; durationMs?: number; traceId?: string;
    bucketId?: string; secretId?: string; details?: { bucket?: string; key?: string; tokenId?: string };
}
interface Elements {
    'login-form': HTMLFormElement; 'bucket-form': HTMLFormElement; 'description-form': HTMLFormElement;
    'secret-form': HTMLFormElement; 'token-form': HTMLFormElement; 'password-form': HTMLFormElement;
    'audit-filter': HTMLFormElement; 'bucket-search': HTMLInputElement; 'value-text': HTMLTextAreaElement;
    'value-dialog': HTMLDialogElement; 'bucket-create': HTMLDetailsElement; 'token-create': HTMLDetailsElement;
    'value-type': HTMLSelectElement; 'config-format': HTMLSelectElement;
}
function $<K extends keyof Elements>(id: K): Elements[K];
function $(id: string): HTMLElement;
function $(id: string): HTMLElement {
    const element = document.getElementById(id);
    if (!element) throw new Error('Missing element: ' + id);
    return element;
}
function control(form: HTMLFormElement, name: string): HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement {
    const element = form.elements.namedItem(name);
    if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement)) throw new Error('Missing form field: ' + name);
    return element;
}
let csrf = '';
let authenticated = false;
let buckets: Bucket[] = [];
let current: Bucket;
let editing: Secret | null = null;
let bucketMetadata: SecretMetadata[] = [];
let configurationSnapshot: BucketSnapshot | null = null;
let routeVersion = 0;
let auditCursor: string | null = null;
let auditCount = 0;
let auditBusy = false;
const scopes = ['secret:read', 'secret:write', 'secret:delete', 'secret:list', 'bucket:create', 'bucket:read', 'bucket:list', 'bucket:delete', 'bucket:write'];
const status = (text: string) => { $('status').textContent = text; $('status').hidden = !text; };
const message = (error: unknown) => status(error instanceof Error ? error.message : 'Request failed');
const date = (value?: string | null) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
const active = (version: number) => authenticated && version === routeVersion;

function clearValue() { $('value-dialog').close(); $('value-text').value = ''; editing = null; }
function clearConfiguration() { configurationSnapshot = null; $('config-output').textContent = ''; $('config-copy').setAttribute('disabled', ''); $('config-download').setAttribute('disabled', ''); }
function lockWorkspace() {
    authenticated = false; routeVersion++; clearValue(); tokenExpiry.close(); clearConfiguration(); bucketMetadata = [];
    $('secret-form').reset(); $('password-form').reset();
    for (const id of ['bucket-list', 'secret-list', 'token-list', 'audit-list']) $(id).replaceChildren();
    $('workspace').hidden = true; $('login').hidden = false; $('loading').hidden = true;
}
async function api<T = unknown>(operation: string, parameters: object = {}): Promise<T> {
    if (operation === 'token.create' || operation === 'bucket.delete') await confirmMfa();
    try { return await execute<T>(operation, parameters, csrf); }
    catch (error) {
        if (error instanceof Error && error.message.includes('Session expired')) lockWorkspace();
        throw error;
    }
}
function action(element: Element, event: string, fn: () => unknown) {
    element.addEventListener(event, async e => {
        e.preventDefault();
        const button = e instanceof SubmitEvent && e.submitter instanceof HTMLButtonElement ? e.submitter : element instanceof HTMLButtonElement ? element : null;
        if (button) button.disabled = true;
        try { status(''); await fn(); } catch (error) { message(error); } finally { if (button) button.disabled = false; }
    });
}
function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls?: string) {
    const element = document.createElement(tag); element.textContent = text; if (cls) element.className = cls; return element;
}
function button(text: string, fn: () => unknown, cls?: string) { const b = node('button', text, cls); b.type = 'button'; action(b, 'click', fn); return b; }
function link(text: string, href: string) { const a = node('a', text); a.href = href; a.dataset.route = ''; return a; }
function icon(name: string) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('icon'); svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('focusable', 'false');
    const use = document.createElementNS(svg.namespaceURI, 'use'); use.setAttribute('href', '#icon-' + name); svg.append(use);
    return svg;
}
function field(parent: HTMLElement, name: string, value: string, title: string) {
    const label = node('label', '', 'check'); const input = document.createElement('input'); input.type = 'checkbox'; input.name = name; input.value = value;
    label.append(input, document.createTextNode(title)); parent.append(label);
}
async function plain(path: string, body: object) {
    const response = await fetch(path, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error('Request rejected (' + response.status + ')');
    return response.json();
}
async function finishMfa(challenge: { mode: string; options: object }): Promise<string[]> {
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON)
        throw new Error('Passkeys require a current browser and an HTTPS domain.');
    const credential = challenge.mode === 'register'
        ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(challenge.options as PublicKeyCredentialCreationOptionsJSON) })
        : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(challenge.options as PublicKeyCredentialRequestOptionsJSON) });
    if (!(credential instanceof PublicKeyCredential)) throw new Error('Passkey verification was cancelled.');
    const result = await plain('/admin/mfa/verify', { credential: credential.toJSON() });
    return result.recoveryCodes;
}
async function confirmMfa() { await finishMfa(await plain('/admin/mfa/options', {})); }
function showRecovery(codes: string[]) {
    if (!codes.length) return;
    editing = null; $('value-title').textContent = 'Save your recovery codes';
    $('value-help').textContent = 'Each code works once with your password to replace a lost passkey. Store offline. Shown only once.';
    $('value-type-label').hidden = true;
    $('value-text').value = codes.join('\n'); $('value-text').readOnly = true; $('save-value').hidden = true; $('value-dialog').showModal();
}
async function session() {
    const response = await fetch('/admin/api/v1/session', { cache: 'no-store', signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error('Session unavailable');
    const s: { authenticated: boolean; csrfToken: string } = await response.json(); csrf = s.csrfToken; authenticated = s.authenticated;
    $('login').hidden = authenticated; $('workspace').hidden = !authenticated;
    if (authenticated) await renderRoute(); else lockWorkspace();
}
async function all<T>(op: string, parameters: object = {}): Promise<T[]> {
    const items: T[] = []; let cursor: string | null = null;
    do { const page: Page<T> = await api<Page<T>>(op, { ...parameters, limit: 200, cursor }); items.push(...page.items); cursor = page.nextCursor; } while (cursor);
    return items;
}
function route() {
    const path = location.pathname.replace(/\/$/, '');
    const match = /^\/admin\/buckets\/([a-z0-9][a-z0-9_-]{0,62})$/.exec(path);
    if (match) return { view: 'secrets', title: match[1], bucket: match[1] };
    const views: Record<string, [string, string]> = { '/admin/buckets': ['buckets', 'Buckets'], '/admin/tokens': ['tokens', 'Access tokens'], '/admin/logs': ['audit', 'Activity logs'], '/admin/settings': ['password', 'Settings'] };
    const entry = views[path]; return { view: entry?.[0] ?? 'not-found', title: entry?.[1] ?? 'Page not found', bucket: '' };
}
function enableBucketControls(enabled: boolean) {
    for (const element of $('secrets-view').querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLButtonElement>('input, textarea, button')) element.disabled = !enabled;
}
async function navigate(path: string, replace = false) {
    if (path !== location.pathname + location.search) history[replace ? 'replaceState' : 'pushState'](null, '', path);
    await renderRoute();
}
async function renderRoute() {
    const version = ++routeVersion; clearValue(); tokenExpiry.close(); clearConfiguration(); $('secret-form').reset(); $('password-form').reset(); status('');
    if (!authenticated) return;
    const { view, title, bucket } = route();
    for (const name of ['buckets', 'secrets', 'tokens', 'audit', 'password', 'not-found']) $(name + '-view').hidden = name !== view;
    for (const a of document.querySelectorAll<HTMLElement>('[data-view]')) {
        if (a.dataset.view === (view === 'secrets' ? 'buckets' : view)) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    }
    $('breadcrumb').textContent = title; document.title = title + ' · DarkVault'; $('loading').hidden = false;
    $('page-content').setAttribute('aria-busy', 'true');
    // Remove stale controls before loading a different bucket or token list.
    if (view === 'secrets') {
        enableBucketControls(false); $('secret-list').replaceChildren(); $('bucket-title').textContent = bucket; $('bucket-description').textContent = '';
        const config = new URLSearchParams(location.search).get('view') === 'configuration';
        $('secret-editor').hidden = config; $('config-panel').hidden = !config;
        for (const [id, selected, suffix] of [['secrets-tab', !config, ''], ['configuration-tab', config, '?view=configuration']] as const) {
            $(id).setAttribute('href', '/admin/buckets/' + encodeURIComponent(bucket) + suffix);
            if (selected) $(id).setAttribute('aria-current', 'page'); else $(id).removeAttribute('aria-current');
        }
    }
    try {
        if (view === 'buckets') await loadBuckets(version);
        if (view === 'secrets') await loadBucket(bucket, version);
        if (view === 'tokens') await loadTokens(version);
        if (view === 'audit') {
            const query = new URLSearchParams(location.search);
            for (const field of ['search', 'kind', 'result']) control($('audit-filter'), field).value = query.get(field) ?? '';
            auditCursor = null; auditCount = 0; auditBusy = false; $('audit-list').replaceChildren(); $('audit-more').hidden = true; $('audit-empty').hidden = true;
            await loadAudit(version);
        }
    } catch (error) { if (version === routeVersion) message(error); }
    finally { if (version === routeVersion) { $('loading').hidden = true; $('page-content').removeAttribute('aria-busy'); } }
}
async function loadBuckets(version = routeVersion) {
    const items = await all<Bucket>('bucket.list'); if (!active(version)) return;
    buckets = items; renderBuckets();
}
function renderBuckets() {
    $('bucket-count').textContent = String(buckets.length); const list = $('bucket-list'); list.replaceChildren();
    const query = $('bucket-search').value.toLowerCase();
    for (const b of buckets.filter(b => b.name.toLowerCase().includes(query) || b.description.toLowerCase().includes(query))) {
        const card = node('article', '', 'card'); const top = node('div', '', 'card-top');
        const mark = node('span', '', 'bucket-icon'); mark.append(icon('buckets')); top.append(mark, node('span', 'Revision ' + b.revision, 'badge neutral'));
        const footer = node('div', '', 'card-footer'); const open = link('Open bucket ', '/admin/buckets/' + encodeURIComponent(b.name)); open.append(icon('right')); open.setAttribute('aria-label', 'Open ' + b.name);
        footer.append(node('small', 'Updated ' + new Date(b.updatedAt).toLocaleDateString()), open);
        card.append(top, node('h2', b.name), node('p', b.description || 'No description provided.'), footer); list.append(card);
    }
    if (!list.childElementCount) list.append(node('p', buckets.length ? 'No buckets match your search.' : 'Your vault is ready. Create your first bucket to get started.', 'empty'));
}
async function loadBucket(name: string, version = routeVersion) {
    const bucket = await api<Bucket>('bucket.get', { bucket: name });
    const items = await all<SecretMetadata>('secret.list', { bucket: name }); if (!active(version)) return;
    current = bucket; bucketMetadata = items; $('bucket-title').textContent = bucket.name; $('bucket-description').textContent = bucket.description || 'Application secrets, securely stored.';
    control($('description-form'), 'description').value = bucket.description; $('secret-count').textContent = items.length + ' secrets';
    const list = $('secret-list'); list.replaceChildren();
    for (const secret of items) {
        const row = node('article', '', 'row'); const body = node('div', '', 'row-body'); const actions = node('div', '', 'actions');
        body.append(node('strong', secret.key), node('small', (secret.type || 'string') + ' · Value hidden · Revision ' + secret.revision + ' · Updated ' + date(secret.updatedAt)));
        actions.append(button('Show / edit', async () => {
            const value = await api<Secret>('secret.read', { bucket: name, key: secret.key }); if (!active(version)) return;
            editing = value; $('value-title').textContent = secret.key; $('value-help').textContent = 'Decrypted locally. Close to clear this field.';
            $('value-type-label').hidden = false; $('value-type').value = value.type || 'string';
            $('value-text').value = value.value; $('value-text').readOnly = false; $('save-value').hidden = false; $('value-dialog').showModal();
        }), button('Delete', async () => {
            if (!confirm('Delete secret ' + secret.key + '?')) return;
            await api('secret.delete', { bucket: name, key: secret.key, expectedRevision: secret.revision }); if (active(version)) await renderRoute();
        }, 'danger'));
        row.append(body, actions); list.append(row);
    }
    if (!items.length) list.append(node('p', 'No secrets yet. Add the first secret above.', 'empty'));
    enableBucketControls(true);
    renderConfiguration();
}
function renderConfiguration() {
    $('config-output').textContent = ''; $('config-error').hidden = true;
    for (const id of ['config-copy', 'config-download']) $(id).setAttribute('disabled', '');
    $('config-hide').hidden = !configurationSnapshot;
    $('config-help').textContent = configurationSnapshot ? 'Values revealed · Snapshot revision ' + configurationSnapshot.revision + '. Exported files contain secrets.' : 'Structure preview only. Placeholders are not a usable configuration.';
    try {
        const values = configurationSnapshot ? typedSecrets(configurationSnapshot) : Object.fromEntries(bucketMetadata.map(s => [s.key, '<hidden:' + (s.type || 'string') + '>']));
        const format = $('config-format').value;
        const tree = buildConfiguration(values, format !== 'flat-json');
        $('config-output').textContent = formatConfiguration(tree, format === 'yaml' ? 'yaml' : 'json');
        if (configurationSnapshot) for (const id of ['config-copy', 'config-download']) $(id).removeAttribute('disabled');
    } catch (error) { $('config-error').textContent = error instanceof Error ? error.message : 'Cannot build configuration.'; $('config-error').hidden = false; }
}
async function loadTokens(version = routeVersion) {
    const [available, tokens] = await Promise.all([all<Bucket>('bucket.list'), all<TokenRecord>('token.list')]); if (!active(version)) return;
    buckets = available; $('token-count').textContent = String(tokens.length);
    // Keep selected grants when refreshing the issued-token list.
    const selected = new Set(new FormData($('token-form')).getAll('bucketIds'));
    $('token-buckets').replaceChildren(node('legend', 'Allowed buckets'));
    for (const b of buckets) field($('token-buckets'), 'bucketIds', b.id, b.name);
    for (const input of $('token-buckets').querySelectorAll('input')) input.checked = selected.has(input.value);
    const list = $('token-list'); list.replaceChildren();
    for (const t of tokens) {
        const i = t.info; const state = t.revokedAt ? 'Revoked' : i.expiresAt && Date.parse(i.expiresAt) <= Date.now() ? 'Expired' : 'Active';
        const row = node('article', '', 'row'); const body = node('div', '', 'row-body'); const heading = node('div', '', 'token-heading');
        heading.append(node('strong', i.name), node('span', state, 'badge ' + (state === 'Active' ? 'success' : 'neutral')));
        const tags = node('div', '', 'scope-tags'); for (const scope of i.scopes) tags.append(node('span', scope));
        body.append(heading, tags, node('p', 'Buckets: ' + (i.allBuckets ? 'All buckets' : i.bucketIds.map(id => buckets.find(b => b.id === id)?.name || id).join(', ') || 'None')),
            node('small', 'Expires: ' + (i.expiresAt ? date(i.expiresAt) : 'Never') + ' · Last used: ' + (t.lastUsedAt ? date(t.lastUsedAt) : 'Never')));
        row.append(body);
        if (!t.revokedAt) row.append(button('Revoke', async () => { if (!confirm('Revoke ' + i.name + '?')) return; await api('token.revoke', { id: i.id }); if (active(version)) await loadTokens(version); }, 'danger'));
        list.append(row);
    }
    if (!tokens.length) list.append(node('p', 'No access tokens yet. Create a token to connect an application.', 'empty'));
}
function auditRow(entry: AuditEntry, index: number) {
    const row = node('tr'); const event = node('td'); const actor = node('td'); const source = node('td'); const result = node('td'); const toggle = node('td');
    event.append(node('strong', entry.operation), node('small', date(entry.time)), node('span', entry.kind === 'http' ? 'HTTP request' : 'Operation', 'event-type'));
    actor.append(node('strong', entry.principalName || (entry.principal === 'anonymous' ? 'Anonymous' : entry.principal)), node('small', entry.principalType || 'Account'));
    source.append(node('strong', entry.sourceIp || 'Local operation'), node('small', entry.method ? entry.method + ' ' + (entry.path || '') : 'Server'));
    result.append(node('span', entry.result === 'success' ? 'Success' : entry.result.replaceAll('_', ' '), 'badge ' + (entry.result === 'success' ? 'success' : 'failure')));
    if (entry.statusCode) result.append(node('small', 'HTTP ' + entry.statusCode + (entry.durationMs != null ? ' · ' + Math.round(entry.durationMs) + ' ms' : '')));
    const detailsRow = node('tr', '', 'log-details'); detailsRow.id = 'audit-detail-' + index; detailsRow.hidden = true;
    const detailsCell = node('td'); detailsCell.colSpan = 5; const grid = node('dl', '', 'detail-grid');
    const fields: [string, string | undefined][] = [['Actor ID', entry.principal], ['Request ID', entry.requestId], ['Trace ID', entry.traceId], ['Peer IP', entry.peerIp], ['Bucket', entry.details?.bucket || entry.bucketId], ['Secret / token', entry.details?.key || entry.secretId || entry.details?.tokenId]];
    for (const [label, value] of fields) { const item = node('div'); item.append(node('dt', label), node('dd', value || '—')); grid.append(item); }
    const raw = node('details'); raw.append(node('summary', 'Full event metadata'), node('pre', JSON.stringify(entry, null, 2)));
    detailsCell.append(grid, raw); detailsRow.append(detailsCell);
    const expand = button('', () => { detailsRow.hidden = !detailsRow.hidden; expand.setAttribute('aria-expanded', String(!detailsRow.hidden)); }, 'expand-button');
    expand.append(icon('chevron'));
    expand.setAttribute('aria-label', 'Event details: ' + entry.operation); expand.setAttribute('aria-controls', detailsRow.id); expand.setAttribute('aria-expanded', 'false');
    toggle.append(expand); row.append(event, actor, source, result, toggle); $('audit-list').append(row, detailsRow);
}
async function loadAudit(version = routeVersion) {
    if (auditBusy) return; auditBusy = true;
    const params = new URLSearchParams(location.search);
    try {
        const page = await api<Page<AuditEntry>>('audit.list', { cursor: auditCursor, limit: 50, order: 'desc', search: params.get('search') || '', kind: params.get('kind') || '', result: params.get('result') || '' });
        if (!active(version)) return;
        for (const entry of page.items) auditRow(entry, auditCount++);
        auditCursor = page.nextCursor; $('audit-more').hidden = !auditCursor; $('audit-empty').hidden = auditCount > 0; $('audit-count').textContent = auditCount + ' events loaded';
    } finally { if (version === routeVersion) auditBusy = false; }
}

document.addEventListener('click', e => {
    if (!(e instanceof MouseEvent) || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || !(e.target instanceof Element)) return;
    const anchor = e.target.closest<HTMLAnchorElement>('a[data-route]'); if (!anchor) return;
    e.preventDefault(); navigate(anchor.pathname + anchor.search).catch(message);
});
window.addEventListener('popstate', () => { renderRoute().catch(message); });
if (['/', '/index.html', '/admin', '/admin/'].includes(location.pathname)) history.replaceState(null, '', '/admin/buckets');
for (const scope of scopes) field($('scopes'), 'scopes', scope, scope);
action($('login-form'), 'submit', async () => { const f = $('login-form'); try {
    const challenge = await plain('/admin/login', { username: control(f, 'username').value, password: control(f, 'password').value, recoveryCode: control(f, 'recovery').value || null });
    const codes = await finishMfa(challenge); await session(); showRecovery(codes);
} finally { control(f, 'password').value = ''; control(f, 'recovery').value = ''; } });
action($('logout'), 'click', async () => { await plain('/admin/logout', {}); lockWorkspace(); await session(); });
action($('new-bucket'), 'click', () => { $('bucket-create').open = true; control($('bucket-form'), 'name').focus(); });
action($('new-token'), 'click', () => { $('token-create').open = true; control($('token-form'), 'name').focus(); });
action($('bucket-form'), 'submit', async () => { const f = $('bucket-form'); const version = routeVersion; await api('bucket.create', { name: control(f, 'name').value, description: control(f, 'description').value }); f.reset(); $('bucket-create').open = false; if (active(version)) await loadBuckets(version); });
$('bucket-search').addEventListener('input', renderBuckets);
action($('description-form'), 'submit', async () => { const version = routeVersion; await api('bucket.update', { bucket: current.name, description: control($('description-form'), 'description').value, expectedRevision: current.revision }); if (active(version)) await renderRoute(); });
action($('secret-form'), 'submit', async () => { const f = $('secret-form'); const version = routeVersion; const type = control(f, 'type').value as SecretType; const value = type === 'null' ? 'null' : control(f, 'value').value; await api('secret.create', { bucket: current.name, key: control(f, 'key').value, ...encodeScalar(parseScalar(value, type)) }); f.reset(); if (active(version)) await renderRoute(); });
action($('delete-bucket'), 'click', async () => {
    const version = routeVersion; const bucket = current; const items = await all<SecretMetadata>('secret.list', { bucket: bucket.name });
    if (!active(version) || prompt('Delete ' + bucket.name + ' and ' + items.length + ' secrets? Type the bucket name:') !== bucket.name) return;
    await api('bucket.delete', { bucket: bucket.name, expectedRevision: bucket.revision, recursive: items.length > 0 }); if (active(version)) await navigate('/admin/buckets');
});
action($('read-profile'), 'click', () => { for (const c of $('scopes').querySelectorAll('input')) c.checked = ['bucket:read', 'secret:read', 'secret:list'].includes(c.value); });
const tokenForm = $('token-form'); const tokenExpiry = setupExpiry(tokenForm);
action(tokenForm, 'submit', async () => {
    if (!tokenExpiry.validate()) return;
    const version = routeVersion; const form = new FormData(tokenForm);
    const result = await api<{ token: string }>('token.create', { name: form.get('name'), scopes: form.getAll('scopes'), bucketIds: form.getAll('bucketIds'), allBuckets: form.has('allBuckets'), creatableBucketNames: String(form.get('creatableBucketNames') ?? '').split(',').map(s => s.trim()).filter(Boolean), expiresAt: new Date(String(form.get('expiry')).replace(' ', 'T')).toISOString() });
    if (!active(version)) return;
    editing = null; $('value-title').textContent = 'Save your access token'; $('value-help').textContent = 'Shown only once. Store securely; it cannot be recovered.';
    $('value-type-label').hidden = true;
    $('value-text').value = result.token; $('value-text').readOnly = true; $('save-value').hidden = true; $('value-dialog').showModal(); $('token-create').open = false; await loadTokens(version);
});
action($('copy-value'), 'click', async () => { await navigator.clipboard.writeText($('value-text').value); status('Copied. Your clipboard may retain this value.'); });
action($('save-value'), 'click', async () => { if (!editing) return; const version = routeVersion; const type = $('value-type').value as SecretType; const value = type === 'null' ? 'null' : $('value-text').value; await api('secret.update', { bucket: current.name, key: editing.key, ...encodeScalar(parseScalar(value, type)), expectedRevision: editing.revision }); clearValue(); if (active(version)) await renderRoute(); });
action($('close-value'), 'click', clearValue);
$('value-dialog').addEventListener('close', () => { $('value-text').value = ''; editing = null; });
action($('password-form'), 'submit', async () => { const f = $('password-form'); try { await confirmMfa(); await plain('/admin/password', { currentPassword: control(f, 'currentPassword').value, newPassword: control(f, 'newPassword').value }); lockWorkspace(); await session(); } finally { f.reset(); } });
action($('add-passkey'), 'click', async () => { await confirmMfa(); const codes = await finishMfa(await plain('/admin/mfa/register', {})); await session(); showRecovery(codes); status('Passkey added. Other sessions have been signed out.'); });
action($('audit-filter'), 'submit', async () => {
    const params = new URLSearchParams(); const form = new FormData($('audit-filter'));
    for (const name of ['search', 'kind', 'result']) { const value = String(form.get(name) || '').trim(); if (value) params.set(name, value); }
    await navigate('/admin/logs' + (params.size ? '?' + params : ''));
});
action($('audit-refresh'), 'click', renderRoute);
action($('audit-more'), 'click', () => loadAudit());
action($('config-reveal'), 'click', async () => {
    const version = routeVersion; const snapshot = await api<BucketSnapshot>('bucket.read', { bucket: current.name });
    if (!active(version)) return; configurationSnapshot = snapshot; renderConfiguration();
});
action($('config-hide'), 'click', () => { clearConfiguration(); renderConfiguration(); });
$('config-format').addEventListener('change', renderConfiguration);
action($('config-copy'), 'click', async () => { if (configurationSnapshot && $('config-output').textContent) { await navigator.clipboard.writeText($('config-output').textContent); status('Configuration copied. Your clipboard contains secrets.'); } });
action($('config-download'), 'click', () => {
    if (!configurationSnapshot || !$('config-output').textContent) return;
    const yaml = $('config-format').value === 'yaml'; const blob = new Blob([$ ('config-output').textContent], { type: yaml ? 'application/yaml' : 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = current.name + (yaml ? '.yaml' : '.json'); a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
for (const submit of document.querySelectorAll<HTMLButtonElement>('form button:not([type="button"])')) submit.disabled = false;
session().catch(message);
