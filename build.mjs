import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

// Define os diretórios de origem e destino
const srcDir = './';
const distDir = './dist';

// Garante que o diretório de destino exista
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Arquivos a serem copiados
const filesToCopy = ['index.html', 'styles.css'];

// Copia os arquivos
filesToCopy.forEach(file => {
  const srcFile = path.join(srcDir, file);
  const destFile = path.join(distDir, file);
  fs.copyFileSync(srcFile, destFile);
});

await esbuild.build({
  entryPoints: ['app.mjs'],
  bundle: true,
  outfile: 'dist/bundle.js',
  format: 'esm',
  minify: true,
  resolveExtensions: ['.mjs', '.js'],
});
