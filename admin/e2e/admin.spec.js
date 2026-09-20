import { test, expect } from '@playwright/test';

test('Admin creates a bucket, edits encrypted secrets, issues and revokes a token',async({page})=>{
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const name='browser_'+Date.now();
  await page.goto('/');await page.getByLabel('Password',{exact:true}).fill('acceptance-test-password-only');await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.locator('#workspace')).toBeVisible();
  await page.locator('#bucket-form').getByLabel('Name',{exact:true}).fill(name);await page.getByRole('button',{name:'Create bucket',exact:true}).click();
  await page.getByRole('button',{name:'Open '+name,exact:true}).click();
  await page.getByLabel('Key',{exact:true}).fill('ConnectionStrings:Main');await page.locator('#secret-form').getByLabel('Value',{exact:true}).fill('browser-secret-秘密');
  const sent=[];page.on('request',r=>{if(r.url().endsWith('/execute'))sent.push(r.postData());});
  await page.getByRole('button',{name:'Add secret',exact:true}).click();await page.getByRole('button',{name:'Show / edit',exact:true}).click();
  await expect(page.locator('#value-text')).toHaveValue('browser-secret-秘密');await page.locator('#value-text').fill('updated');await page.getByRole('button',{name:'Save change',exact:true}).click();
  await page.getByRole('button',{name:'Show / edit',exact:true}).click();await expect(page.locator('#value-text')).toHaveValue('updated');await page.getByRole('button',{name:'Close and clear',exact:true}).click();await expect(page.locator('#value-text')).toHaveValue('');
  await page.getByRole('button',{name:'Access tokens',exact:true}).click();await page.locator('#token-form').getByLabel('Name',{exact:true}).fill('browser-token');await page.getByRole('button',{name:'Select bucket reader scopes'}).click();await page.locator('#token-buckets').getByLabel(name,{exact:true}).check();
  await page.getByRole('button',{name:'Create token',exact:true}).click();await expect(page.locator('#value-text')).toHaveValue(/^dv1_[A-Za-z0-9_-]{60}$/);await page.getByRole('button',{name:'Close and clear',exact:true}).click();
  page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Revoke',exact:true}).last().click();await expect(page.locator('#token-list')).toContainText('Revoked');
  await page.screenshot({path:'test-results/admin-tokens.png',fullPage:true});
  await page.getByRole('button',{name:'Audit',exact:true}).click();await expect(page.locator('#audit-list')).toContainText('bucket.create');
  await page.getByRole('button',{name:'Password',exact:true}).click();
  await page.getByLabel('Current password',{exact:true}).fill('acceptance-test-password-only');await page.getByLabel('New password',{exact:true}).fill('acceptance-test-password-updated');
  await page.getByRole('button',{name:'Change password and sign out',exact:true}).click();await expect(page.locator('#login')).toBeVisible();
  await page.getByLabel('Password',{exact:true}).fill('acceptance-test-password-updated');await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.locator('#workspace')).toBeVisible();
  await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.locator('#login')).toBeVisible();
  expect(errors).toEqual([]);expect(sent.length).toBeGreaterThan(0);expect(sent.every(body=>body&&!body.includes('browser-secret')&&!body.includes('updated')&&body.split('.').length===5)).toBe(true);
});
