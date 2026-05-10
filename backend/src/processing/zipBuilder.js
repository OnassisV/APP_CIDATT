// Empaqueta entregables (Word + Excel + posibles xlsx por unidad) en un ZIP en memoria.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver');

export function buildZipBuffer(files) {
  return new Promise((resolve, reject) => {
    const archive = new ZipArchive({ zlib: { level: 9 } });
    const chunks = [];
    archive.on('data', (c) => chunks.push(c));
    archive.on('end', () => resolve(Buffer.concat(chunks)));
    archive.on('error', reject);
    for (const f of files) {
      archive.append(f.buffer, { name: f.name });
    }
    archive.finalize();
  });
}
