import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('dist', { recursive: true });
await build({ entryPoints: ['src/app.ts'], bundle: true, format: 'esm', minify: true, outfile: 'dist/app.js' });
// Keep the browser transport independently testable without shipping it twice.
await build({ entryPoints: ['src/protocol.ts'], bundle: true, format: 'esm', platform: 'node', packages: 'external', outfile: 'dist/protocol.js' });
await Promise.all(['index.html', 'style.css'].map(name => copyFile(name, `dist/${name}`)));
