import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['app.mjs'],
  bundle: true,
  outfile: 'bundle.js',
  format: 'esm',
  minify: true,
});
