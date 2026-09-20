import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function needsPublish(status, output, integrity) {
  const result = JSON.parse(output);
  if (status !== 0) {
    if (result.error?.code === 'E404') return true;
    throw new Error('Cannot query npm; publication stopped');
  }
  if (result !== integrity) throw new Error('Published npm archive differs from this release');
  return false;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [archive, version] = process.argv.slice(2);
  if (!archive || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? '')) {
    throw new Error('Usage: node tools/publish-npm.mjs <archive> <stable-version>');
  }
  const registry = '--registry=https://registry.npmjs.org';
  const integrity = `sha512-${createHash('sha512').update(readFileSync(archive)).digest('base64')}`;
  const lookup = spawnSync('npm', ['view', `@darkvault/client@${version}`, 'dist.integrity', '--json', registry], { encoding: 'utf8' });
  if (lookup.error) throw lookup.error;
  if (needsPublish(lookup.status, lookup.stdout, integrity)) {
    const result = spawnSync('npm', ['publish', archive, '--access=public', '--ignore-scripts', registry], { stdio: 'inherit' });
    if (result.error) throw result.error;
    process.exitCode = result.status ?? 1;
  } else {
    console.log(`@darkvault/client@${version} already published with identical bytes`);
  }
}
