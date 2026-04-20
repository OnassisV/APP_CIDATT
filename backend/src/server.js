import 'dotenv/config';

import bcrypt from 'bcrypt';
import crypto from 'crypto';
import cors from 'cors';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

import { query, withTransaction } from './db.js';

const app = express();
const port = Number(process.env.PORT || 3000);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendDir = path.resolve(__dirname, '../../frontend');

const TABLES = {
  users: 'cidatt_auth_users',
  tokens: 'cidatt_auth_tokens',
  sessions: 'cidatt_shift_sessions',
  profiles: 'cidatt_shift_profiles',
  records: 'cidatt_vehicle_records'
};

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(frontendDir));

function badRequest(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function unauthorized(message = 'No autorizado.') {
  const error = new Error(message);
  error.status = 401;
  return error;
}

function hashText(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  return header.slice(7).trim();
}

async function authenticateRequest(req, _res, next) {
  try {
    const token = getBearerToken(req);
    if (!token) throw unauthorized('Falta token de acceso.');

    const tokenHash = hashText(token);
    const rows = await query(
      `
        SELECT
          t.id,
          t.user_id,
          t.expires_at,
          u.username,
          u.full_name,
          u.is_active
        FROM ${TABLES.tokens} t
        INNER JOIN ${TABLES.users} u ON u.id = t.user_id
        WHERE t.token_hash = ?
          AND t.expires_at > NOW()
        LIMIT 1
      `,
      [tokenHash]
    );

    if (!rows.length || !rows[0].is_active) throw unauthorized('Sesion invalida o expirada.');
    req.authUser = rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

function mapSessionPayload(body = {}) {
  if (!body.id) throw badRequest('Falta id de sesion.');
  if (!body.operationDate) throw badRequest('Falta fecha de operacion.');
  if (!Array.isArray(body.profiles) || body.profiles.length === 0) {
    throw badRequest('Faltan perfiles de caseta.');
  }

  return {
    id: String(body.id),
    operationDate: String(body.operationDate),
    multi: Boolean(body.multi),
    activeIndex: Number(body.activeIndex || 0),
    status: String(body.status || 'open'),
    profiles: body.profiles.map((profile, index) => ({
      profileIndex: index,
      tollName: String(profile.nombrePeaje || ''),
      boothNumber: String(profile.numeroCaseta || ''),
      operatorName: String(profile.operador || ''),
      direction: String(profile.sentidoCirculacion || '')
    }))
  };
}

function mapRecordPayload(body = {}) {
  const requiredFields = ['id', 'sessionId', 'fecha', 'horaPaso', 'placaPrincipal', 'tipoVehiculo'];

  for (const field of requiredFields) {
    if (!body[field]) throw badRequest(`Falta ${field}.`);
  }

  return {
    id: String(body.id),
    sessionId: String(body.sessionId),
    operationDate: String(body.fecha),
    tollName: String(body.nombrePeaje || ''),
    boothNumber: String(body.numeroCaseta || ''),
    direction: String(body.sentidoCirculacion || ''),
    operatorName: String(body.operador || ''),
    passedAt: String(body.horaPaso),
    mainPlate: String(body.placaPrincipal),
    vehicleType: String(body.tipoVehiculo),
    mainAxles: Number(body.ejesPrincipal || 0),
    secondaryPlate: body.placaSecundaria ? String(body.placaSecundaria) : null,
    secondaryAxles: Number(body.ejesSecundaria || 0),
    totalAxles: Number(body.totalEjes || 0),
    syncStatus: String(body.syncStatus || 'synced')
  };
}

app.get('/healthz', (_req, res) => {
  res.json({ ok: true, service: 'rlv-cidatt' });
});

app.get('/api/health', async (_req, res) => {
  try {
    await query('SELECT 1 AS ok');
    res.json({ ok: true, database: true });
  } catch (error) {
    res.status(500).json({ ok: false, database: false, error: error.message });
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) throw badRequest('Usuario y clave son obligatorios.');

    const users = await query(
      `
        SELECT id, username, full_name, password_hash, is_active
        FROM ${TABLES.users}
        WHERE username = ?
        LIMIT 1
      `,
      [username]
    );

    if (!users.length || !users[0].is_active) throw unauthorized('Credenciales invalidas.');

    const validPassword = await bcrypt.compare(password, users[0].password_hash);
    if (!validPassword) throw unauthorized('Credenciales invalidas.');

    const plainToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashText(plainToken);

    await query(
      `
        INSERT INTO ${TABLES.tokens} (user_id, token_hash, expires_at)
        VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))
      `,
      [users[0].id, tokenHash]
    );

    res.json({
      ok: true,
      token: plainToken,
      user: {
        id: users[0].id,
        username: users[0].username,
        fullName: users[0].full_name
      }
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', authenticateRequest, async (req, res) => {
  res.json({
    ok: true,
    user: {
      id: req.authUser.user_id,
      username: req.authUser.username,
      fullName: req.authUser.full_name
    }
  });
});

app.post('/api/sessions/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const session = mapSessionPayload(req.body);

    await withTransaction(async (connection) => {
      await connection.execute(
        `
          INSERT INTO ${TABLES.sessions} (
            id,
            operation_date,
            is_multi,
            active_profile_index,
            status
          ) VALUES (?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            operation_date = VALUES(operation_date),
            is_multi = VALUES(is_multi),
            active_profile_index = VALUES(active_profile_index),
            status = VALUES(status)
        `,
        [session.id, session.operationDate, session.multi ? 1 : 0, session.activeIndex, session.status]
      );

      await connection.execute(`DELETE FROM ${TABLES.profiles} WHERE session_id = ?`, [session.id]);

      for (const profile of session.profiles) {
        await connection.execute(
          `
            INSERT INTO ${TABLES.profiles} (
              session_id,
              profile_index,
              toll_name,
              booth_number,
              operator_name,
              direction
            ) VALUES (?, ?, ?, ?, ?, ?)
          `,
          [
            session.id,
            profile.profileIndex,
            profile.tollName,
            profile.boothNumber,
            profile.operatorName,
            profile.direction
          ]
        );
      }
    });

    res.json({ ok: true, sessionId: session.id });
  } catch (error) {
    next(error);
  }
});

app.get('/api/sessions/:id', authenticateRequest, async (req, res, next) => {
  try {
    const sessions = await query(`SELECT * FROM ${TABLES.sessions} WHERE id = ?`, [req.params.id]);
    if (!sessions.length) return res.status(404).json({ ok: false, error: 'Sesion no encontrada.' });

    const profiles = await query(
      `SELECT profile_index, toll_name, booth_number, operator_name, direction FROM ${TABLES.profiles} WHERE session_id = ? ORDER BY profile_index ASC`,
      [req.params.id]
    );

    res.json({ ok: true, session: sessions[0], profiles });
  } catch (error) {
    next(error);
  }
});

app.post('/api/records/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const record = mapRecordPayload(req.body);

    await query(
      `
        INSERT INTO ${TABLES.records} (
          id,
          session_id,
          operation_date,
          toll_name,
          booth_number,
          direction,
          operator_name,
          passed_at,
          main_plate,
          vehicle_type,
          main_axles,
          secondary_plate,
          secondary_axles,
          total_axles,
          sync_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          session_id = VALUES(session_id),
          operation_date = VALUES(operation_date),
          toll_name = VALUES(toll_name),
          booth_number = VALUES(booth_number),
          direction = VALUES(direction),
          operator_name = VALUES(operator_name),
          passed_at = VALUES(passed_at),
          main_plate = VALUES(main_plate),
          vehicle_type = VALUES(vehicle_type),
          main_axles = VALUES(main_axles),
          secondary_plate = VALUES(secondary_plate),
          secondary_axles = VALUES(secondary_axles),
          total_axles = VALUES(total_axles),
          sync_status = VALUES(sync_status)
      `,
      [
        record.id,
        record.sessionId,
        record.operationDate,
        record.tollName,
        record.boothNumber,
        record.direction,
        record.operatorName,
        record.passedAt,
        record.mainPlate,
        record.vehicleType,
        record.mainAxles,
        record.secondaryPlate,
        record.secondaryAxles,
        record.totalAxles,
        record.syncStatus
      ]
    );

    res.json({ ok: true, recordId: record.id });
  } catch (error) {
    next(error);
  }
});

app.get('/api/records', authenticateRequest, async (req, res, next) => {
  try {
    const filters = [];
    const params = [];

    if (req.query.sessionId) {
      filters.push('session_id = ?');
      params.push(String(req.query.sessionId));
    }

    if (req.query.operationDate) {
      filters.push('operation_date = ?');
      params.push(String(req.query.operationDate));
    }

    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const rows = await query(
      `
        SELECT *
        FROM ${TABLES.records}
        ${where}
        ORDER BY operation_date DESC, passed_at DESC, created_at DESC
      `,
      params
    );

    res.json({ ok: true, rows });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/records/:id', authenticateRequest, async (req, res, next) => {
  try {
    await query(`DELETE FROM ${TABLES.records} WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get(/^\/(?!api).*/, (_req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

app.use((error, _req, res, _next) => {
  const status = error.status || 500;
  res.status(status).json({ ok: false, error: error.message || 'Error interno.' });
});

async function runMigrations() {
  console.log('Ejecutando migraciones...');

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.users} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      username VARCHAR(80) NOT NULL,
      full_name VARCHAR(120) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_auth_users_username (username)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.tokens} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      token_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_auth_tokens_hash (token_hash),
      KEY idx_cidatt_auth_tokens_user_id (user_id),
      CONSTRAINT fk_cidatt_auth_tokens_user FOREIGN KEY (user_id) REFERENCES ${TABLES.users} (id) ON DELETE CASCADE
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.sessions} (
      id CHAR(36) NOT NULL,
      operation_date DATE NOT NULL,
      is_multi TINYINT(1) NOT NULL DEFAULT 0,
      active_profile_index INT NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_cidatt_shift_sessions_operation_date (operation_date)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.profiles} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      session_id CHAR(36) NOT NULL,
      profile_index INT NOT NULL,
      toll_name VARCHAR(120) NOT NULL,
      booth_number VARCHAR(30) NOT NULL,
      operator_name VARCHAR(120) NOT NULL,
      direction VARCHAR(60) NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_shift_profiles_session_profile (session_id, profile_index),
      CONSTRAINT fk_cidatt_shift_profiles_session FOREIGN KEY (session_id) REFERENCES ${TABLES.sessions} (id) ON DELETE CASCADE
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.records} (
      id CHAR(36) NOT NULL,
      session_id CHAR(36) NOT NULL,
      operation_date DATE NOT NULL,
      toll_name VARCHAR(120) NOT NULL,
      booth_number VARCHAR(30) NOT NULL,
      direction VARCHAR(60) NOT NULL,
      operator_name VARCHAR(120) NOT NULL,
      passed_at TIME NOT NULL,
      main_plate VARCHAR(20) NOT NULL,
      vehicle_type VARCHAR(20) NOT NULL,
      main_axles INT NOT NULL,
      secondary_plate VARCHAR(20) NULL,
      secondary_axles INT NOT NULL DEFAULT 0,
      total_axles INT NOT NULL,
      sync_status VARCHAR(20) NOT NULL DEFAULT 'synced',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_cidatt_vehicle_records_session_id (session_id),
      KEY idx_cidatt_vehicle_records_operation_date (operation_date),
      KEY idx_cidatt_vehicle_records_main_plate (main_plate),
      CONSTRAINT fk_cidatt_vehicle_records_session FOREIGN KEY (session_id) REFERENCES ${TABLES.sessions} (id) ON DELETE CASCADE
    )
  `);

  // Seed admin user con bcrypt
  const existing = await query(`SELECT id FROM ${TABLES.users} WHERE username = 'admin' LIMIT 1`);
  if (!existing.length) {
    const hash = await bcrypt.hash('CIDATT2026!', 12);
    await query(
      `INSERT INTO ${TABLES.users} (username, full_name, password_hash, is_active) VALUES (?, ?, ?, 1)`,
      ['admin', 'Administrador CIDATT', hash]
    );
    console.log('Usuario admin creado.');
  }

  console.log('Migraciones completadas.');
}

async function start() {
  await runMigrations();
  app.listen(port, () => {
    console.log(`RLV CIDATT escuchando en http://localhost:${port}`);
  });
}

start().catch((err) => {
  console.error('Error al iniciar:', err);
  process.exit(1);
});
