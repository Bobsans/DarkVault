import { execute } from './protocol.js';
import type { Bucket, Secret, SecretMetadata, Page, TokenInfo } from '@darkvault/client';

interface TokenRecord { info: TokenInfo; revokedAt: string | null; lastUsedAt: string | null }
interface Elements {
    'login-form': HTMLFormElement; 'bucket-form': HTMLFormElement; 'description-form': HTMLFormElement;
    'secret-form': HTMLFormElement; 'token-form': HTMLFormElement; 'password-form': HTMLFormElement;
    'bucket-search': HTMLInputElement; 'value-text': HTMLTextAreaElement; 'value-dialog': HTMLDialogElement;
}
function $<K extends keyof Elements>(id: K): Elements[K];
function $(id: string): HTMLElement;
function $(id: string): HTMLElement {
    const element = document.getElementById(id);
    if (!element) throw new Error('Missing element: ' + id);
    return element;
}
function control(form: HTMLFormElement, name: string): HTMLInputElement | HTMLTextAreaElement {
    const element = form.elements.namedItem(name);
    if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)) throw new Error('Missing form field: ' + name);
    return element;
}
let csrf = '';
let buckets: Bucket[] = [];
let current: Bucket;
let editing: Secret | null = null;
let auditCursor: string | null = null;
const scopes = ['secret:read','secret:write','secret:delete','secret:list','bucket:create','bucket:read','bucket:list','bucket:delete','bucket:write'];
const status = (text: string) => { $('status').textContent = text; };
const api = <T = unknown>(operation: string, parameters: object = {}) => execute<T>(operation, parameters, csrf);
function action(element: Element, event: string, fn: () => unknown) { element.addEventListener(event, async e => { e.preventDefault(); const button = (e instanceof SubmitEvent && e.submitter instanceof HTMLButtonElement ? e.submitter : null) || (element instanceof HTMLButtonElement ? element : null); if(button) button.disabled = true; try { status(''); await fn(); } catch(error) { status(error instanceof Error ? error.message : 'Request failed'); } finally { if(button) button.disabled = false; } }); }
function node<K extends keyof HTMLElementTagNameMap>(tag: K, text: string, cls?: string) { const n = document.createElement(tag); n.textContent = text; if(cls) n.className = cls; return n; }
function button(text: string, fn: () => unknown) { const b = node('button', text); action(b, 'click', fn); return b; }
function field(parent: HTMLElement, name: string, value: string, title: string) { const label = node('label', '', 'check'); const input = document.createElement('input'); input.type='checkbox'; input.name=name; input.value=value; label.append(input,document.createTextNode(title)); parent.append(label); }
async function plain(path: string, body: object) { const r = await fetch(path, { method:'POST', redirect:'error', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify(body), signal:AbortSignal.timeout(30000) }); if(!r.ok) throw new Error('Request rejected ('+r.status+')'); return r.json(); }
async function session() { const r = await fetch('/admin/api/v1/session',{cache:'no-store'}); if (!r.ok) throw new Error('Session unavailable'); const s: {authenticated: boolean; csrfToken: string} = await r.json(); csrf=s.csrfToken; $('login').hidden=s.authenticated; $('workspace').hidden=!s.authenticated; $('logout').hidden=!s.authenticated; if(s.authenticated) await show('buckets'); }
async function all<T>(op: string, parameters: object = {}): Promise<T[]> { const items: T[]=[]; let cursor: string | null=null; do { const page: Page<T>=await api<Page<T>>(op,{...parameters,limit:200,cursor}); items.push(...page.items); cursor=page.nextCursor; } while(cursor); return items; }
async function show(view: string) { for(const name of ['buckets','secrets','tokens','audit','password']) $(name+'-view').hidden=name!==view; if(view==='buckets') await loadBuckets(); if(view==='tokens') await loadTokens(); if(view==='audit') { $('audit-list').replaceChildren(); auditCursor=null; await loadAudit(); } }
async function loadBuckets() { buckets=await all<Bucket>('bucket.list'); renderBuckets(); }
function renderBuckets() { $('bucket-list').replaceChildren(); const query=$('bucket-search').value.toLowerCase(); for(const b of buckets.filter(b=>b.name.includes(query))) { const card=node('article','', 'card'); card.append(node('h2',b.name),node('p',b.description),button('Open '+b.name,()=>openBucket(b.name))); $('bucket-list').append(card); } }
async function openBucket(name: string) { current=await api<Bucket>('bucket.get',{bucket:name}); await show('secrets'); $('bucket-title').textContent=current.name; $('bucket-description').textContent=current.description; control($('description-form'),'description').value=current.description; const items=await all<SecretMetadata>('secret.list',{bucket:name}); $('secret-list').replaceChildren(); for(const s of items) { const row=node('article','', 'row'); row.append(node('strong',s.key),node('small','Value hidden · revision '+s.revision),button('Show / edit',async()=>{const value=await api<Secret>('secret.read',{bucket:name,key:s.key}); editing=value; $('value-title').textContent=s.key; $('value-help').textContent='Decrypted locally. Close to clear this field.'; $('value-text').value=value.value; $('value-text').readOnly=false; $('save-value').hidden=false; $('value-dialog').showModal();}),button('Delete',async()=>{if(!confirm('Delete secret '+s.key+'?'))return; await api('secret.delete',{bucket:name,key:s.key,expectedRevision:s.revision});await openBucket(name);})); $('secret-list').append(row); } }
async function loadTokens() { await loadBuckets(); $('token-buckets').replaceChildren(node('legend','Allowed buckets')); for(const b of buckets) field($('token-buckets'),'bucketIds',b.id,b.name); const tokens=await all<TokenRecord>('token.list'); $('token-list').replaceChildren(); for(const t of tokens) { const row=node('article','', 'row'); const i=t.info; row.append(node('strong',i.name),node('p',(t.revokedAt?'Revoked':i.expiresAt && Date.parse(i.expiresAt)<=Date.now()?'Expired':'Active')+' · '+(i.expiresAt||'Never expires')),node('p',i.scopes.join(', ')),node('small','Buckets: '+(i.allBuckets?'ALL':i.bucketIds.map(id=>buckets.find(b=>b.id===id)?.name||id).join(', '))+' · Last used: '+(t.lastUsedAt||'Never'))); if(!t.revokedAt)row.append(button('Revoke',async()=>{if(!confirm('Revoke '+i.name+'?'))return; await api('token.revoke',{id:i.id});await loadTokens();})); $('token-list').append(row); } }
async function loadAudit() { const page=await api<Page<Record<string, unknown>>>('audit.list',{cursor:auditCursor,limit:100}); for(const e of page.items) $('audit-list').append(node('pre',JSON.stringify(e,null,2),'row')); auditCursor=page.nextCursor; $('audit-more').hidden=!auditCursor; }
for(const s of scopes) field($('scopes'),'scopes',s,s);
for(const b of document.querySelectorAll<HTMLButtonElement>('[data-view]'))action(b,'click',()=>show(b.dataset.view!));
action($('login-form'),'submit',async()=>{const f=$('login-form');try{await plain('/admin/login',{username:control(f,'username').value,password:control(f,'password').value});await session();}finally{control(f,'password').value='';}});
action($('logout'),'click',async()=>{await plain('/admin/logout',{});location.reload();});
action($('bucket-form'),'submit',async()=>{const f=$('bucket-form');await api('bucket.create',{name:control(f,'name').value,description:control(f,'description').value});f.reset();await loadBuckets();});
$('bucket-search').addEventListener('input',renderBuckets);
action($('back'),'click',()=>show('buckets'));
action($('description-form'),'submit',async()=>{await api('bucket.update',{bucket:current.name,description:control($('description-form'),'description').value,expectedRevision:current.revision});await openBucket(current.name);});
action($('secret-form'),'submit',async()=>{const f=$('secret-form');await api('secret.create',{bucket:current.name,key:control(f,'key').value,value:control(f,'value').value});f.reset();await openBucket(current.name);});
action($('delete-bucket'),'click',async()=>{const items=await all<SecretMetadata>('secret.list',{bucket:current.name});if(prompt('Delete '+current.name+' and '+items.length+' secrets? Type the bucket name:')!==current.name)return;await api('bucket.delete',{bucket:current.name,expectedRevision:current.revision,recursive:items.length>0});await show('buckets');});
action($('read-profile'),'click',()=>{for(const c of $('scopes').querySelectorAll('input'))c.checked=['bucket:read','secret:read','secret:list'].includes(c.value);});
const tokenForm=$('token-form'); const expiry=new Date(Date.now()+30*86400000); control(tokenForm,'expiry').value=new Date(expiry.getTime()-expiry.getTimezoneOffset()*60000).toISOString().slice(0,16);
const never = control(tokenForm, 'never') as HTMLInputElement;
never.addEventListener('change',()=>{control(tokenForm, 'expiry').disabled=never.checked;});
action(tokenForm,'submit',async()=>{const f=new FormData(tokenForm);const result=await api<{token: string}>('token.create',{name:f.get('name'),scopes:f.getAll('scopes'),bucketIds:f.getAll('bucketIds'),allBuckets:f.has('allBuckets'),creatableBucketNames:String(f.get('creatableBucketNames') ?? '').split(',').map(s=>s.trim()).filter(Boolean),expiresAt:f.has('never')?null:new Date(String(f.get('expiry'))).toISOString()});editing=null;$('value-title').textContent='Save your access token';$('value-help').textContent='Shown only once. Store securely; it cannot be recovered.';$('value-text').value=result.token;$('value-text').readOnly=true;$('save-value').hidden=true;$('value-dialog').showModal();await loadTokens();});
action($('copy-value'),'click',async()=>{await navigator.clipboard.writeText($('value-text').value);status('Copied. Your clipboard may retain this value.');});
action($('save-value'),'click',async()=>{if (!editing) return;await api('secret.update',{bucket:current.name,key:editing.key,value:$('value-text').value,expectedRevision:editing.revision});$('value-dialog').close();await openBucket(current.name);});
action($('close-value'),'click',()=>$('value-dialog').close());
$('value-dialog').addEventListener('close',()=>{$('value-text').value='';editing=null;});
action($('password-form'),'submit',async()=>{const f=$('password-form');try{await plain('/admin/password',{currentPassword:control(f,'currentPassword').value,newPassword:control(f,'newPassword').value});location.reload();}finally{f.reset();}});
action($('audit-more'),'click',loadAudit);
for (const submit of document.querySelectorAll<HTMLButtonElement>('form button:not([type="button"])')) submit.disabled = false;
session().catch(e=>status(e.message));
