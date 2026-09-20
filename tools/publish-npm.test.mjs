import assert from 'node:assert/strict';
import { test } from 'node:test';
import { needsPublish } from './publish-npm.mjs';

test('npm publication only accepts an absent version or identical archive', () => {
  assert.equal(needsPublish(1, '{"error":{"code":"E404"}}', 'sha512-test'), true);
  assert.equal(needsPublish(0, '"sha512-test"', 'sha512-test'), false);
  assert.throws(() => needsPublish(0, '"sha512-other"', 'sha512-test'), /differs/);
  assert.throws(() => needsPublish(1, '{"error":{"code":"E401"}}', 'sha512-test'), /stopped/);
  assert.throws(() => needsPublish(1, '{"error":{"code":"E503"}}', 'sha512-test'), /stopped/);
  assert.throws(() => needsPublish(null, '', 'sha512-test'));
});
