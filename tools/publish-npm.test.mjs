import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { needsPublish, publishArchive } from './publish-npm.mjs';

test('npm publication only accepts an absent version or identical archive', () => {
  assert.equal(needsPublish(1, '{"error":{"code":"E404"}}', 'sha512-test'), true);
  assert.equal(needsPublish(0, '"sha512-test"', 'sha512-test'), false);
  assert.throws(() => needsPublish(0, '"sha512-other"', 'sha512-test'), /differs/);
  assert.throws(() => needsPublish(1, '{"error":{"code":"E401"}}', 'sha512-test'), /stopped/);
  assert.throws(() => needsPublish(1, '{"error":{"code":"E503"}}', 'sha512-test'), /stopped/);
  assert.throws(() => needsPublish(null, '', 'sha512-test'));
});

test('relative tarball paths are published as local files, never GitHub shorthand', () => {
  const directory = mkdtempSync(join(tmpdir(), 'darkvault-npm-'));
  const previous = process.cwd();
  try {
    process.chdir(directory);
    mkdirSync('packages');
    writeFileSync('packages/client.tgz', 'public test archive');
    const calls = [];
    const result = publishArchive('packages/client.tgz', '2.0.0', (command, args) => {
      assert.equal(command, 'npm'); calls.push(args);
      return args[0] === 'view' ? { status: 1, stdout: '{"error":{"code":"E404"}}' } : { status: 0 };
    });
    assert.equal(result, 0);
    assert.deepEqual(calls[1], ['publish', resolve('packages/client.tgz'), '--access=public', '--ignore-scripts', '--registry=https://registry.npmjs.org']);
  } finally {
    process.chdir(previous);
    assert.ok(directory.startsWith(join(tmpdir(), 'darkvault-npm-')));
    rmSync(directory, { recursive: true });
  }
});
