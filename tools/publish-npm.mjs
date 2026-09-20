import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export function needsPublish(status, output, integrity) {
  const result = JSON.parse(output);
  if (status !== 0) {
    if (result.error?.code === 'E404') return true;
    throw new Error('Cannot query npm; publication stopped');
  }
  if (result !== integrity) throw new Error('Published npm archive differs from this release');
  return false;
}

export function publishArchive(archivePath, version, run = spawnSync) {
  if (!archivePath || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? '')) {
    throw new Error('Usage: node tools/publish-npm.mjs <archive> <stable-version>');
  }
  // npm treats paths such as packages/client.tgz as GitHub shorthand.
  const archive = resolve(archivePath);
  const registry = '--registry=https://registry.npmjs.org';
  const integrity = `sha512-${createHash('sha512').update(readFileSync(archive)).digest('base64')}`;
  const lookup = run('npm', ['view', `@darkvault/client@${version}`, 'dist.integrity', '--json', registry], { encoding: 'utf8' });
  if (lookup.error) throw lookup.error;
  if (needsPublish(lookup.status, lookup.stdout, integrity)) {
    const result = run('npm', ['publish', archive, '--access=public', '--ignore-scripts', registry], { stdio: 'inherit' });
    if (result.error) throw result.error;
    return result.status ?? 1;
  } else {
    console.log(`@darkvault/client@${version} already published with identical bytes`);
    return 0;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = publishArchive(...process.argv.slice(2));
}
