// Script de configuración local: crea la BD, aplica el schema y crea usuario director.
// Uso: node scripts/local-setup.mjs
// Requiere MySQL corriendo en 127.0.0.1:3306 (DBngin u otro).

import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dir = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = path.join(__dir, '../db/schema.sql');

const cfg = {
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: '',        // cambiar si tu MySQL local tiene contraseña
  multipleStatements: true
};

async function main() {
  console.log('Conectando a MySQL local…');
  const conn = await mysql.createConnection(cfg);

  // Crear base si no existe
  await conn.query('CREATE DATABASE IF NOT EXISTS railway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
  await conn.query('USE railway');
  console.log('✓ Base de datos "railway" lista.');

  // Aplicar schema (ignorar USE railway; al inicio — ya hicimos USE arriba)
  const schema = fs.readFileSync(SCHEMA, 'utf8').replace(/^USE\s+railway\s*;/m, '');
  await conn.query(schema);
  console.log('✓ Schema aplicado.');

  // Crear usuario director si no existe
  const [rows] = await conn.query("SELECT id FROM cidatt_auth_users WHERE username = 'director' LIMIT 1");
  if (rows.length) {
    console.log('ℹ  Usuario "director" ya existe — no se toca.');
  } else {
    const hash = await bcrypt.hash('admin123', 10);
    await conn.query(
      `INSERT INTO cidatt_auth_users (username, full_name, password_hash, role, is_active)
       VALUES ('director', 'Director Local', ?, 'director', 1)`,
      [hash]
    );
    console.log('✓ Usuario creado:  director / admin123');
  }

  await conn.end();
  console.log('\n✅ Listo. Ejecutá: npm run dev   (dentro de la carpeta backend)');
  console.log('   Luego abrí:    http://localhost:3000');
}

main().catch(e => {
  console.error('❌ Error:', e.message);
  process.exit(1);
});
