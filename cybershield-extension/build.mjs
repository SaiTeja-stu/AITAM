import * as esbuild from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';

const watch = process.argv.includes('--watch');
const outdir = 'dist';

rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

// Static assets (manifest, HTML, icons)
cpSync('public', outdir, { recursive: true });

/** @type {esbuild.BuildOptions} */
const opts = {
  entryPoints: {
    background: 'src/background.ts',
    content: 'src/content.ts',
    popup: 'src/popup.ts',
    options: 'src/options.ts',
  },
  bundle: true,
  format: 'esm',
  target: 'es2022',
  outdir,
  logLevel: 'info',
  sourcemap: watch ? 'inline' : false,
};

if (watch) {
  const ctx = await esbuild.context(opts);
  await ctx.watch();
  console.log('watching…');
} else {
  await esbuild.build(opts);
  console.log('built -> dist/  (load unpacked in chrome://extensions)');
}
