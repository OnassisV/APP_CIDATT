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
  users:       'cidatt_auth_users',
  tokens:      'cidatt_auth_tokens',
  sessions:    'cidatt_shift_sessions',
  profiles:    'cidatt_shift_profiles',
  records:     'cidatt_vehicle_records',
  projects:    'cidatt_projects',
  concessions: 'cidatt_concessions',
  stations:    'cidatt_toll_stations',
  booths:      'cidatt_toll_booths',
  projectSites:'cidatt_project_sites',
  assignments: 'cidatt_user_assignments',
  presence:    'cidatt_device_presence'
};

// Jerarquía de roles
const ROLE_LEVEL = { admin: 4, director: 3, coordinador: 2, registrador: 1 };

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(frontendDir));

function badRequest(message) { const e = new Error(message); e.status = 400; return e; }
function unauthorized(message = 'No autorizado.') { const e = new Error(message); e.status = 401; return e; }
function forbidden(message = 'Acceso denegado.') { const e = new Error(message); e.status = 403; return e; }

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
      `SELECT t.id, t.user_id, t.expires_at, u.username, u.full_name, u.role, u.is_active
       FROM ${TABLES.tokens} t
       INNER JOIN ${TABLES.users} u ON u.id = t.user_id
       WHERE t.token_hash = ? AND t.expires_at > NOW() LIMIT 1`,
      [tokenHash]
    );
    if (!rows.length || !rows[0].is_active) throw unauthorized('Sesion invalida o expirada.');
    req.authUser = rows[0];
    next();
  } catch (error) { next(error); }
}

function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.authUser) return next(unauthorized());
    if (!roles.includes(req.authUser.role)) return next(forbidden(`Se requiere rol: ${roles.join(' o ')}.`));
    next();
  };
}

function requireMinRole(minRole) {
  return (req, _res, next) => {
    if (!req.authUser) return next(unauthorized());
    const userLevel = ROLE_LEVEL[req.authUser.role] || 0;
    const minLevel  = ROLE_LEVEL[minRole] || 0;
    if (userLevel < minLevel) return next(forbidden('Permisos insuficientes.'));
    next();
  };
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

function mapSessionPayload(body = {}) {
  if (!body.id) throw badRequest('Falta id de sesion.');
  if (!body.operationDate) throw badRequest('Falta fecha de operacion.');
  if (!Array.isArray(body.profiles) || body.profiles.length === 0) throw badRequest('Faltan perfiles de caseta.');
  const profiles = body.profiles.map((p, i) => ({
    profileIndex: i,
    tollName: String(p.nombrePeaje || ''),
    boothNumber: String(p.numeroCaseta || ''),
    operatorName: String(p.operador || ''),
    direction: String(p.sentidoCirculacion || ''),
    projectId: parseOptionalInt(p.projectId),
    stationId: parseOptionalInt(p.stationId),
    boothId: parseOptionalInt(p.boothId)
  }));
  const profileProjectIds = [...new Set(profiles.map((profile) => profile.projectId).filter(Boolean))];
  const profileStationIds = [...new Set(profiles.map((profile) => profile.stationId).filter(Boolean))];
  return {
    id: String(body.id),
    operationDate: String(body.operationDate),
    multi: Boolean(body.multi),
    activeIndex: Number(body.activeIndex || 0),
    status: String(body.status || 'open'),
    projectId: profileProjectIds.length === 1 ? profileProjectIds[0] : parseOptionalInt(body.projectId),
    stationId: profileStationIds.length === 1 ? profileStationIds[0] : parseOptionalInt(body.stationId),
    profiles
  };
}

function mapRecordPayload(body = {}) {
  for (const f of ['id', 'sessionId', 'fecha', 'horaPaso', 'placaPrincipal', 'tipoVehiculo']) {
    if (!body[f]) throw badRequest(`Falta ${f}.`);
  }
  return {
    id: String(body.id), sessionId: String(body.sessionId),
    operationDate: String(body.fecha), tollName: String(body.nombrePeaje || ''),
    boothNumber: String(body.numeroCaseta || ''), direction: String(body.sentidoCirculacion || ''),
    operatorName: String(body.operador || ''), passedAt: String(body.horaPaso),
    mainPlate: String(body.placaPrincipal), vehicleType: String(body.tipoVehiculo),
    mainAxles: Number(body.ejesPrincipal || 0),
    secondaryPlate: body.placaSecundaria ? String(body.placaSecundaria) : null,
    secondaryAxles: Number(body.ejesSecundaria || 0), totalAxles: Number(body.totalEjes || 0),
    syncStatus: String(body.syncStatus || 'synced'),
    projectId: parseOptionalInt(body.projectId),
    stationId: parseOptionalInt(body.stationId),
    boothId: parseOptionalInt(body.boothId),
    isFugitive: body.isFugitive ? 1 : 0
  };
}

function normalizeText(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function parseOptionalInt(value) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return Math.round(numeric);
}

function parseCsvIds(value) {
  return String(value || '')
    .split(',')
    .map((item) => parseOptionalInt(item))
    .filter(Boolean);
}

function sanitizeMaxBoothsPerOperator(value) {
  const parsed = Number(value || 2);
  if (!Number.isFinite(parsed)) return 2;
  return Math.max(1, Math.min(2, Math.round(parsed)));
}

async function ensureDefaultConcession() {
  const defaultName = 'Concesion General';
  const rows = await query(`SELECT id FROM ${TABLES.concessions} WHERE name = ? LIMIT 1`, [defaultName]);
  if (rows.length) return rows[0].id;
  const result = await query(`INSERT INTO ${TABLES.concessions} (name, status) VALUES (?, 'activa')`, [defaultName]);
  return result.insertId;
}

async function resolveConcessionId({ concessionId, concessionName, fallbackToDefault = true } = {}) {
  const numericId = Number(concessionId || 0);
  if (numericId) return numericId;
  const trimmedName = String(concessionName || '').trim();
  if (trimmedName) {
    const existingConcession = await query(
      `SELECT id FROM ${TABLES.concessions} WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1`,
      [trimmedName]
    );
    if (existingConcession.length) return existingConcession[0].id;
    const result = await query(`INSERT INTO ${TABLES.concessions} (name, status) VALUES (?, 'activa')`, [trimmedName]);
    return result.insertId;
  }
  return fallbackToDefault ? ensureDefaultConcession() : null;
}

async function getPresenceStateForUserProject(userId, projectId) {
  const rows = await query(
    `SELECT last_heartbeat_at
     FROM ${TABLES.presence}
     WHERE user_id = ? AND project_id = ?
     ORDER BY last_heartbeat_at DESC
     LIMIT 1`,
    [userId, projectId]
  );
  if (!rows.length || !rows[0].last_heartbeat_at) return 'offline';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(rows[0].last_heartbeat_at).getTime()) / 1000));
  if (seconds <= 45) return 'online';
  if (seconds <= 120) return 'idle';
  return 'offline';
}

async function getCoordinatorManagedStations(userId, projectId = null) {
  const filters = ['user_id = ?', "booth_id IS NULL", 'is_active = 1', `station_id IS NOT NULL`];
  const params = [userId];
  const numericProjectId = parseOptionalInt(projectId);
  if (numericProjectId) {
    filters.push('project_id = ?');
    params.push(numericProjectId);
  }
  const rows = await query(
    `SELECT DISTINCT project_id, station_id
     FROM ${TABLES.assignments}
     WHERE ${filters.join(' AND ')}`,
    params
  );
  return rows.map((row) => ({
    projectId: Number(row.project_id),
    stationId: Number(row.station_id)
  }));
}

async function assertProjectAccess(authUser, projectId, { stationId = null } = {}) {
  const numericProjectId = parseOptionalInt(projectId);
  if (!numericProjectId) throw badRequest('Proyecto invalido.');
  if (['admin', 'director'].includes(authUser.role)) {
    return { projectId: numericProjectId, managedStationIds: [] };
  }
  if (authUser.role === 'coordinador') {
    const managedStations = await getCoordinatorManagedStations(authUser.user_id, numericProjectId);
    if (!managedStations.length) throw forbidden('No tienes acceso a este proyecto.');
    const managedStationIds = managedStations.map((item) => item.stationId);
    const numericStationId = parseOptionalInt(stationId);
    if (numericStationId && !managedStationIds.includes(numericStationId)) {
      throw forbidden('No tienes acceso a este peaje dentro del proyecto.');
    }
    return { projectId: numericProjectId, managedStationIds };
  }
  if (authUser.role === 'registrador') {
    const rows = await query(
      `SELECT 1
       FROM ${TABLES.assignments}
       WHERE user_id = ? AND project_id = ? AND is_active = 1
       LIMIT 1`,
      [authUser.user_id, numericProjectId]
    );
    if (!rows.length) throw forbidden('No tienes acceso a este proyecto.');
    return { projectId: numericProjectId, managedStationIds: [] };
  }
  throw forbidden('No tienes acceso a este proyecto.');
}

async function getSessionContext(sessionId) {
  const rows = await query(
    `SELECT s.id, s.operation_date, s.is_multi, s.active_profile_index, s.status,
            s.owner_user_id, s.project_id, s.station_id, s.created_at, s.updated_at,
            GROUP_CONCAT(DISTINCT sp.station_id ORDER BY sp.station_id SEPARATOR ',') AS profile_station_ids
     FROM ${TABLES.sessions} s
     LEFT JOIN ${TABLES.profiles} sp ON sp.session_id = s.id
     WHERE s.id = ?
     GROUP BY s.id
     LIMIT 1`,
    [sessionId]
  );
  return rows[0] || null;
}

async function assertSessionAccess(authUser, sessionId, options = {}) {
  const session = typeof sessionId === 'object' && sessionId !== null ? sessionId : await getSessionContext(sessionId);
  if (!session) throw badRequest('Sesion no encontrada.');
  if (['admin', 'director'].includes(authUser.role)) return session;
  if (authUser.role === 'registrador') {
    const allowOwnSession = options.allowRegistradorOwn !== false;
    if (allowOwnSession && Number(session.owner_user_id || 0) === Number(authUser.user_id)) return session;
    throw forbidden('No tienes acceso a este turno.');
  }
  if (authUser.role === 'coordinador') {
    if (!session.project_id) throw forbidden('El turno no esta vinculado a un proyecto coordinable.');
    const access = await assertProjectAccess(authUser, session.project_id);
    const managedStationIds = access.managedStationIds || [];
    const sessionStationIds = [...new Set([
      parseOptionalInt(session.station_id),
      ...parseCsvIds(session.profile_station_ids)
    ].filter(Boolean))];
    if (!sessionStationIds.length) throw forbidden('El turno no tiene un peaje operativo valido.');
    if (!sessionStationIds.some((id) => managedStationIds.includes(id))) {
      throw forbidden('No tienes acceso a este turno.');
    }
    return session;
  }
  throw forbidden('No tienes acceso a este turno.');
}

async function closeOpenSessionsForScope({ projectId = null, stationId = null, boothId = null, stationName = '', boothCode = '' } = {}) {
  const filters = [`s.status = 'open'`];
  const params = [];
  const numericProjectId = parseOptionalInt(projectId);
  const numericStationId = parseOptionalInt(stationId);
  const numericBoothId = parseOptionalInt(boothId);
  const trimmedStationName = String(stationName || '').trim();
  const trimmedBoothCode = String(boothCode || '').trim();

  if (numericProjectId) {
    filters.push(`s.project_id = ?`);
    params.push(numericProjectId);
  }

  if (numericBoothId) {
    const boothFilters = [`p.booth_id = ?`];
    params.push(numericBoothId);
    if (trimmedStationName && trimmedBoothCode) {
      boothFilters.push(`(p.booth_id IS NULL AND LOWER(TRIM(p.toll_name)) = LOWER(TRIM(?)) AND p.booth_number = ?)`);
      params.push(trimmedStationName, trimmedBoothCode);
    }
    filters.push(`(${boothFilters.join(' OR ')})`);
  } else {
    const stationFilters = [];
    if (numericStationId) {
      stationFilters.push(`COALESCE(s.station_id, p.station_id) = ?`);
      params.push(numericStationId);
    }
    if (trimmedStationName) {
      stationFilters.push(`LOWER(TRIM(p.toll_name)) = LOWER(TRIM(?))`);
      params.push(trimmedStationName);
    }
    if (!stationFilters.length) return 0;
    filters.push(`(${stationFilters.join(' OR ')})`);
  }

  const result = await query(
    `UPDATE ${TABLES.sessions} s
     LEFT JOIN ${TABLES.profiles} p ON p.session_id = s.id
     SET s.status = 'closed'
     WHERE ${filters.join(' AND ')}`,
    params
  );
  return Number(result.affectedRows || 0);
}

async function getAssignmentsForUser(userId) {
  const rows = await query(
    `SELECT a.id, a.project_id, COALESCE(a.station_id, tb.station_id) AS station_id, a.booth_id, a.created_at,
            p.name AS project_name, COALESCE(p.max_booths_per_operator, 2) AS max_booths_per_operator,
            ts.name AS station_name, ts.location AS station_location, ts.concession_id,
            c.name AS concession_name, tb.code AS booth_code, tb.directions
     FROM ${TABLES.assignments} a
     LEFT JOIN ${TABLES.projects} p ON p.id = a.project_id
     LEFT JOIN ${TABLES.booths} tb ON tb.id = a.booth_id
     LEFT JOIN ${TABLES.stations} ts ON ts.id = COALESCE(a.station_id, tb.station_id)
     LEFT JOIN ${TABLES.concessions} c ON c.id = ts.concession_id
     WHERE a.user_id = ? AND a.is_active = 1
     ORDER BY a.booth_id IS NULL DESC, ts.name ASC, tb.code ASC, a.created_at DESC`,
    [userId]
  );

  const assignments = rows.map((row) => ({
    id: row.id,
    projectId: row.project_id,
    projectName: row.project_name,
    stationId: row.station_id,
    stationName: row.station_name,
    stationLocation: row.station_location,
    concessionId: row.concession_id,
    concessionName: row.concession_name,
    boothId: row.booth_id,
    boothCode: row.booth_code,
    directions: row.directions,
    maxBoothsPerOperator: Number(row.max_booths_per_operator || 2),
    type: row.booth_id ? 'booth' : 'pool'
  }));

  const boothAssignments = assignments.filter((item) => item.boothId);
  const poolAssignments = assignments.filter((item) => !item.boothId);

  return {
    assignments,
    primaryAssignment: boothAssignments[0] || poolAssignments[0] || null,
    operationContext: {
      boothAssignments,
      poolAssignments,
      maxBoothsPerOperator: boothAssignments[0]?.maxBoothsPerOperator || poolAssignments[0]?.maxBoothsPerOperator || 2
    }
  };
}

async function getProjectStations(projectId) {
  const stations = await query(
    `SELECT ts.id, ts.name, ts.location, ts.daily_start_time, ts.daily_end_time,
            ts.concession_id, c.name AS concession_name, ps.id AS project_site_id,
            COALESCE(p.max_booths_per_operator, 2) AS max_booths_per_operator,
            u.id AS coord_user_id, u.full_name AS coord_name, a.id AS coord_assignment_id
     FROM ${TABLES.projectSites} ps
     INNER JOIN ${TABLES.stations} ts ON ts.id = ps.station_id
     INNER JOIN ${TABLES.projects} p ON p.id = ps.project_id
     LEFT JOIN ${TABLES.concessions} c ON c.id = ts.concession_id
     LEFT JOIN ${TABLES.assignments} a
       ON a.station_id = ts.id AND a.project_id = ps.project_id AND a.booth_id IS NULL AND a.is_active = 1
       AND a.user_id IN (SELECT id FROM ${TABLES.users} su WHERE su.role = 'coordinador')
     LEFT JOIN ${TABLES.users} u ON u.id = a.user_id
     WHERE ps.project_id = ? AND ps.is_active = 1
     ORDER BY c.name ASC, ts.name ASC`,
    [projectId]
  );

  if (!stations.length) return stations;

  const stationIds = stations.map((station) => station.id);
  const placeholders = stationIds.map(() => '?').join(',');
  const boothParams = [projectId, projectId, projectId, ...stationIds];
  const regParams = [projectId, ...stationIds];

  const allBooths = await query(
    `SELECT tb.id, tb.station_id, tb.code, tb.directions,
            a.id AS assignment_id, u.id AS assigned_user_id, u.full_name AS assigned_user_name, u.username AS assigned_username,
            (SELECT COUNT(*) FROM ${TABLES.records} r
             WHERE r.project_id = ? AND r.operation_date = CURDATE()
               AND (r.booth_id = tb.id OR (r.booth_id IS NULL AND r.booth_number = tb.code AND r.toll_name = ts2.name))) AS records_today,
            (SELECT IF(COUNT(*) > 0, 1, 0)
             FROM ${TABLES.sessions} ss
             JOIN ${TABLES.profiles} sp ON sp.session_id = ss.id
             WHERE ss.status = 'open' AND ss.operation_date = CURDATE()
               AND ss.project_id = ? AND (sp.booth_id = tb.id OR (sp.booth_id IS NULL AND sp.toll_name = ts2.name AND sp.booth_number = tb.code))) AS has_open_shift
     FROM ${TABLES.booths} tb
     INNER JOIN ${TABLES.stations} ts2 ON ts2.id = tb.station_id
     LEFT JOIN ${TABLES.assignments} a ON a.booth_id = tb.id AND a.project_id = ? AND a.is_active = 1
     LEFT JOIN ${TABLES.users} u ON u.id = a.user_id
     WHERE tb.station_id IN (${placeholders})
     ORDER BY tb.station_id, tb.code`,
    boothParams
  );

  const allRegs = await query(
    `SELECT u.id, u.full_name, a.id AS assignment_id, a.station_id
     FROM ${TABLES.assignments} a
     JOIN ${TABLES.users} u ON u.id = a.user_id
     WHERE a.project_id = ? AND a.station_id IN (${placeholders})
       AND a.booth_id IS NULL AND a.is_active = 1 AND u.role = 'registrador'
     ORDER BY a.station_id, u.full_name`,
    regParams
  );

  stations.forEach((station) => {
    station.booths = allBooths.filter((booth) => booth.station_id === station.id);
    station.station_regs = allRegs.filter((user) => user.station_id === station.id);
  });

  return stations;
}

// ─── HEALTHCHECK ──────────────────────────────────────────────────────────────

app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'rlv-cidatt' }));

app.get('/api/health', async (_req, res) => {
  try { await query('SELECT 1 AS ok'); res.json({ ok: true, database: true }); }
  catch (error) { res.status(500).json({ ok: false, database: false, error: error.message }); }
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!username || !password) throw badRequest('Usuario y clave son obligatorios.');

    const users = await query(
      `SELECT id, username, full_name, role, password_hash, is_active FROM ${TABLES.users} WHERE username = ? LIMIT 1`,
      [username]
    );
    if (!users.length || !users[0].is_active) throw unauthorized('Credenciales invalidas.');
    const valid = await bcrypt.compare(password, users[0].password_hash);
    if (!valid) throw unauthorized('Credenciales invalidas.');

    const plainToken = crypto.randomBytes(32).toString('hex');
    const tokenHash  = hashText(plainToken);
    await query(
      `INSERT INTO ${TABLES.tokens} (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))`,
      [users[0].id, tokenHash]
    );

    const assignmentData = await getAssignmentsForUser(users[0].id);

    res.json({
      ok: true, token: plainToken,
      user: {
        id: users[0].id, username: users[0].username,
        fullName: users[0].full_name, role: users[0].role
      },
      assignment: assignmentData.primaryAssignment,
      assignments: assignmentData.assignments,
      operationContext: assignmentData.operationContext
    });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', authenticateRequest, async (req, res) => {
  const assignmentData = await getAssignmentsForUser(req.authUser.user_id);
  res.json({
    ok: true,
    user: { id: req.authUser.user_id, username: req.authUser.username, fullName: req.authUser.full_name, role: req.authUser.role },
    assignment: assignmentData.primaryAssignment,
    assignments: assignmentData.assignments,
    operationContext: assignmentData.operationContext
  });
});

app.get('/api/my/operation-context', authenticateRequest, async (req, res, next) => {
  try {
    const assignmentData = await getAssignmentsForUser(req.authUser.user_id);
    res.json({
      ok: true,
      assignments: assignmentData.assignments,
      operationContext: assignmentData.operationContext
    });
  } catch (error) { next(error); }
});

// ─── USUARIOS (admin y director pueden gestionar) ─────────────────────────────

app.get('/api/users', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const myLevel = ROLE_LEVEL[req.authUser.role] || 0;
    // Solo puede ver usuarios de rol inferior al suyo
    const rows = await query(
      `SELECT u.id, u.username, u.full_name, u.role, u.is_active, u.created_at,
              (SELECT p.name FROM ${TABLES.assignments} a
               JOIN ${TABLES.projects} p ON p.id = a.project_id
               WHERE a.user_id = u.id AND a.is_active = 1
               ORDER BY a.created_at DESC LIMIT 1) AS project_name
       FROM ${TABLES.users} u
       ORDER BY project_name IS NULL ASC, project_name ASC, u.role ASC, u.full_name ASC`
    );
    const filtered = req.authUser.role === 'admin'
      ? rows
      : rows.filter(u => (ROLE_LEVEL[u.role] || 0) < myLevel);
    res.json({ ok: true, users: filtered });
  } catch (error) { next(error); }
});

app.post('/api/users', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { username, full_name, password, role } = req.body;
    if (!username || !full_name || !password || !role) throw badRequest('Faltan campos obligatorios.');

    const myLevel    = ROLE_LEVEL[req.authUser.role] || 0;
    const targetLevel = ROLE_LEVEL[role] || 0;
    if (targetLevel >= myLevel) throw forbidden('No puedes crear usuarios con rol igual o superior al tuyo.');

    const exists = await query(`SELECT id FROM ${TABLES.users} WHERE username = ? LIMIT 1`, [username]);
    if (exists.length) throw badRequest('El nombre de usuario ya existe.');

    const hash = await bcrypt.hash(password, 12);
    const result = await query(
      `INSERT INTO ${TABLES.users} (username, full_name, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)`,
      [String(username).trim(), String(full_name).trim(), hash, role]
    );
    res.json({ ok: true, userId: result.insertId });
  } catch (error) { next(error); }
});

app.put('/api/users/:id', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { full_name, is_active, password } = req.body;
    const target = await query(`SELECT id, role FROM ${TABLES.users} WHERE id = ? LIMIT 1`, [req.params.id]);
    if (!target.length) throw badRequest('Usuario no encontrado.');

    const myLevel     = ROLE_LEVEL[req.authUser.role] || 0;
    const targetLevel = ROLE_LEVEL[target[0].role] || 0;
    if (targetLevel >= myLevel) throw forbidden('No puedes editar usuarios con rol igual o superior al tuyo.');

    if (full_name !== undefined) {
      await query(`UPDATE ${TABLES.users} SET full_name = ? WHERE id = ?`, [String(full_name).trim(), req.params.id]);
    }
    if (is_active !== undefined) {
      await query(`UPDATE ${TABLES.users} SET is_active = ? WHERE id = ?`, [is_active ? 1 : 0, req.params.id]);
    }
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      await query(`UPDATE ${TABLES.users} SET password_hash = ? WHERE id = ?`, [hash, req.params.id]);
    }
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── CONCESIONES ──────────────────────────────────────────────────────────────

app.get('/api/concessions', authenticateRequest, requireMinRole('coordinador'), async (_req, res, next) => {
  try {
    const rows = await query(
      `SELECT id, name, status
       FROM ${TABLES.concessions}
       WHERE LOWER(TRIM(name)) NOT IN ('concesion general', 'concesión general', 'general')
       ORDER BY name ASC`
    );
    res.json({ ok: true, concessions: rows });
  } catch (error) { next(error); }
});

app.post('/api/concessions', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    if (!name) throw badRequest('El nombre de la concesion es obligatorio.');
    const existing = await query(`SELECT id FROM ${TABLES.concessions} WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1`, [name]);
    if (existing.length) return res.json({ ok: true, concessionId: existing[0].id, reused: true });
    const result = await query(`INSERT INTO ${TABLES.concessions} (name, status) VALUES (?, 'activa')`, [name]);
    res.json({ ok: true, concessionId: result.insertId, reused: false });
  } catch (error) { next(error); }
});

// ─── PROYECTOS ────────────────────────────────────────────────────────────────

app.get('/api/projects', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    let rows;
    if (['admin', 'director'].includes(req.authUser.role)) {
      rows = await query(
        `SELECT p.*, c.name AS concession_name
         FROM ${TABLES.projects} p
         LEFT JOIN ${TABLES.concessions} c ON c.id = p.concession_id
         ORDER BY p.start_date DESC`
      );
    } else {
      // Coordinador: solo sus proyectos asignados
      rows = await query(
        `SELECT DISTINCT p.*, c.name AS concession_name FROM ${TABLES.projects} p
         LEFT JOIN ${TABLES.concessions} c ON c.id = p.concession_id
         INNER JOIN ${TABLES.assignments} a ON a.project_id = p.id
         WHERE a.user_id = ? AND a.is_active = 1 ORDER BY p.start_date DESC`,
        [req.authUser.user_id]
      );
    }
    // Agregar contadores y progreso por proyecto
    for (const p of rows) {
      const [counts] = await query(
        `SELECT COUNT(*) AS total_records,
                COUNT(DISTINCT session_id) AS total_sessions
         FROM ${TABLES.records}
         WHERE project_id = ? OR (project_id IS NULL AND toll_name IN (
           SELECT DISTINCT ts.name
           FROM ${TABLES.projectSites} ps
           INNER JOIN ${TABLES.stations} ts ON ts.id = ps.station_id
           WHERE ps.project_id = ? AND ps.is_active = 1
         ))`,
        [p.id, p.id]
      );
      const [boothCounts] = await query(
        `SELECT COUNT(*) AS total_booths,
                COUNT(DISTINCT CASE WHEN a.user_id IS NOT NULL AND a.is_active = 1 THEN a.booth_id END) AS staffed_booths,
                COUNT(DISTINCT ts.concession_id) AS total_concessions
         FROM ${TABLES.booths} tb
         INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
         INNER JOIN ${TABLES.projectSites} ps ON ps.station_id = ts.id AND ps.project_id = ? AND ps.is_active = 1
         LEFT JOIN ${TABLES.assignments} a ON a.booth_id = tb.id AND a.project_id = ? AND a.is_active = 1`,
        [p.id, p.id]
      );
      const [stationCounts] = await query(
        `SELECT COUNT(DISTINCT station_id) AS total_sites
         FROM ${TABLES.projectSites}
         WHERE project_id = ? AND is_active = 1`,
        [p.id]
      );
      p.total_records  = counts.total_records;
      p.total_sessions = counts.total_sessions;
      p.total_booths   = boothCounts.total_booths;
      p.staffed_booths = boothCounts.staffed_booths;
      p.total_concessions = boothCounts.total_concessions;
      p.total_sites = stationCounts.total_sites;
    }
    res.json({ ok: true, projects: rows });
  } catch (error) { next(error); }
});

app.post('/api/projects', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, description, start_date, end_date, max_booths_per_operator, concession_id, concession_name } = req.body;
    if (!name || !start_date) throw badRequest('Nombre y fecha inicio son obligatorios.');
    const resolvedConcessionId = await resolveConcessionId({ concessionId: concession_id, concessionName: concession_name, fallbackToDefault: false });
    const result = await query(
      `INSERT INTO ${TABLES.projects} (name, description, start_date, end_date, concession_id, max_booths_per_operator, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [String(name).trim(), description||null, start_date, end_date||null, resolvedConcessionId, sanitizeMaxBoothsPerOperator(max_booths_per_operator), req.authUser.user_id]
    );
    res.json({ ok: true, projectId: result.insertId });
  } catch (error) { next(error); }
});

app.put('/api/projects/:id', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, description, start_date, end_date, daily_start_time, daily_end_time, status, max_booths_per_operator, concession_id, concession_name } = req.body;
    const resolvedConcessionId = concession_id || concession_name
      ? await resolveConcessionId({ concessionId: concession_id, concessionName: concession_name, fallbackToDefault: false })
      : null;
    await query(
      `UPDATE ${TABLES.projects} SET name=COALESCE(?,name), description=COALESCE(?,description),
       start_date=COALESCE(?,start_date), end_date=COALESCE(?,end_date),
       daily_start_time=COALESCE(?,daily_start_time), daily_end_time=COALESCE(?,daily_end_time),
       status=COALESCE(?,status), concession_id=COALESCE(?, concession_id),
       max_booths_per_operator=COALESCE(?,max_booths_per_operator) WHERE id=?`,
      [name||null, description||null, start_date||null, end_date||null,
       daily_start_time||null, daily_end_time||null, status||null,
       resolvedConcessionId, max_booths_per_operator != null ? sanitizeMaxBoothsPerOperator(max_booths_per_operator) : null, req.params.id]
    );
    res.json({ ok: true });
  } catch (error) { next(error); }
});


app.delete('/api/projects/:id', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const projectId = Number(req.params.id || 0);
    if (!projectId) throw badRequest('Proyecto invalido.');
    const [activeAssignments] = await query(
      `SELECT COUNT(*) AS total FROM ${TABLES.assignments} WHERE project_id = ? AND is_active = 1`,
      [projectId]
    );
    if (Number(activeAssignments?.total || 0) > 0) {
      throw badRequest('No se puede eliminar el proyecto porque tiene personal asignado. Retira las asignaciones primero.');
    }
    await withTransaction(async (conn) => {
      await conn.execute(`UPDATE ${TABLES.projectSites} SET is_active = 0 WHERE project_id = ?`, [projectId]);
      await conn.execute(`DELETE FROM ${TABLES.projects} WHERE id = ?`, [projectId]);
    });
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── ESTACIONES / CASETAS ─────────────────────────────────────────────────────

app.get('/api/projects/:projectId/stations', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const access = await assertProjectAccess(req.authUser, req.params.projectId);
    let stations = await getProjectStations(access.projectId);
    if (req.authUser.role === 'coordinador') {
      const allowedStationIds = new Set((access.managedStationIds || []).map((id) => Number(id)));
      stations = stations.filter((station) => allowedStationIds.has(Number(station.id)));
    }
    const [projectRow] = await query(`SELECT name FROM ${TABLES.projects} WHERE id = ? LIMIT 1`, [req.params.projectId]);
    res.json({ ok: true, stations, projectName: projectRow?.name || '' });
  } catch (error) { next(error); }
});

app.post('/api/projects/:projectId/stations', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, location, daily_start_time, daily_end_time, concession_id, concession_name } = req.body;
    if (!name) throw badRequest('Nombre de estación requerido.');
    const resolvedConcessionId = await resolveConcessionId({ concessionId: concession_id, concessionName: concession_name });

    const existingStation = await query(
      `SELECT id FROM ${TABLES.stations}
       WHERE concession_id = ? AND LOWER(TRIM(name)) = LOWER(TRIM(?))
       LIMIT 1`,
      [resolvedConcessionId, String(name).trim()]
    );

    let stationId;
    let reused = false;
    if (existingStation.length) {
      stationId = existingStation[0].id;
      reused = true;
    } else {
      const result = await query(
        `INSERT INTO ${TABLES.stations} (project_id, concession_id, name, location, daily_start_time, daily_end_time)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [null, resolvedConcessionId, String(name).trim(), location || null, daily_start_time || null, daily_end_time || null]
      );
      stationId = result.insertId;
    }

    const existingLink = await query(
      `SELECT id, is_active FROM ${TABLES.projectSites} WHERE project_id = ? AND station_id = ? LIMIT 1`,
      [req.params.projectId, stationId]
    );
    if (existingLink.length && Number(existingLink[0].is_active) === 1) {
      throw badRequest('Ese peaje ya está vinculado al proyecto.');
    }
    if (existingLink.length) {
      await query(`UPDATE ${TABLES.projectSites} SET is_active = 1, linked_by = ? WHERE id = ?`, [req.authUser.user_id, existingLink[0].id]);
    } else {
      await query(
        `INSERT INTO ${TABLES.projectSites} (project_id, station_id, linked_by, is_active) VALUES (?, ?, ?, 1)`,
        [req.params.projectId, stationId, req.authUser.user_id]
      );
    }

    res.json({ ok: true, stationId, reused });
  } catch (error) { next(error); }
});

app.get('/api/stations/template', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const name = String(req.query.name || '').trim();
    if (!name) throw badRequest('Nombre de peaje requerido.');
    const concessionId = await resolveConcessionId({
      concessionId: req.query.concession_id,
      concessionName: req.query.concession_name,
      fallbackToDefault: false
    });
    if (!concessionId) return res.json({ ok: true, template: null });
    const rows = await query(
      `SELECT ts.id, ts.name, ts.location, ts.daily_start_time, ts.daily_end_time, ts.updated_at,
              c.id AS concession_id, c.name AS concession_name
       FROM ${TABLES.stations} ts
       INNER JOIN ${TABLES.concessions} c ON c.id = ts.concession_id
       WHERE ts.concession_id = ? AND LOWER(TRIM(ts.name)) = LOWER(TRIM(?))
       ORDER BY ts.id DESC
       LIMIT 1`,
      [concessionId, name]
    );
    if (!rows.length) return res.json({ ok: true, template: null });
    const booths = await query(
      `SELECT code, directions
       FROM ${TABLES.booths}
       WHERE station_id = ?
       ORDER BY code ASC`,
      [rows[0].id]
    );
    res.json({
      ok: true,
      template: {
        id: rows[0].id,
        name: rows[0].name,
        location: rows[0].location,
        daily_start_time: rows[0].daily_start_time,
        daily_end_time: rows[0].daily_end_time,
        concession_id: rows[0].concession_id,
        concession_name: rows[0].concession_name,
        booths
      }
    });
  } catch (error) { next(error); }
});

app.put('/api/stations/:stationId', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, location, daily_start_time, daily_end_time, concession_id } = req.body;
    if (!name) throw badRequest('Nombre de estación requerido.');
    await query(
      `UPDATE ${TABLES.stations} SET name=?, location=?, daily_start_time=?, daily_end_time=?, concession_id=COALESCE(?, concession_id) WHERE id=?`,
      [String(name).trim(), location || null, daily_start_time || null, daily_end_time || null, concession_id || null, req.params.stationId]
    );
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.post('/api/stations/:stationId/booths', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { code, directions } = req.body;
    if (!code) throw badRequest('Código de caseta requerido.');
    const result = await query(
      `INSERT INTO ${TABLES.booths} (station_id, code, directions) VALUES (?, ?, ?)`,
      [req.params.stationId, String(code).trim(), directions || '']
    );
    res.json({ ok: true, boothId: result.insertId });
  } catch (error) { next(error); }
});

app.delete('/api/stations/:stationId', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const [station] = await query(`SELECT id, name FROM ${TABLES.stations} WHERE id = ? LIMIT 1`, [req.params.stationId]);
    if (!station) throw badRequest('Peaje no encontrado.');
    const projectId = Number(req.query.projectId || 0);
    if (projectId) {
      await closeOpenSessionsForScope({ projectId, stationId: station.id, stationName: station.name });
      await query(
        `UPDATE ${TABLES.assignments}
         SET is_active = 0
         WHERE project_id = ? AND (station_id = ? OR booth_id IN (SELECT id FROM ${TABLES.booths} WHERE station_id = ?))`,
        [projectId, req.params.stationId, req.params.stationId]
      );
      await query(`DELETE FROM ${TABLES.projectSites} WHERE project_id = ? AND station_id = ?`, [projectId, req.params.stationId]);
      const [remainingLinks] = await query(
        `SELECT COUNT(*) AS total FROM ${TABLES.projectSites} WHERE station_id = ? AND is_active = 1`,
        [req.params.stationId]
      );
      if (Number(remainingLinks?.total || 0) === 0) {
        await closeOpenSessionsForScope({ stationId: station.id, stationName: station.name });
        await query(`UPDATE ${TABLES.assignments} SET is_active = 0 WHERE station_id = ?`, [req.params.stationId]);
        await query(`DELETE FROM ${TABLES.stations} WHERE id = ?`, [req.params.stationId]);
      }
    } else {
      await closeOpenSessionsForScope({ stationId: station.id, stationName: station.name });
      await query(`UPDATE ${TABLES.assignments} SET is_active = 0 WHERE station_id = ?`, [req.params.stationId]);
      await query(`DELETE FROM ${TABLES.projectSites} WHERE station_id = ?`, [req.params.stationId]);
      await query(`DELETE FROM ${TABLES.stations} WHERE id = ?`, [req.params.stationId]);
    }
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.delete('/api/booths/:boothId', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const [booth] = await query(
      `SELECT tb.id, tb.code, tb.station_id, ts.name AS station_name
       FROM ${TABLES.booths} tb
       INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
       WHERE tb.id = ?
       LIMIT 1`,
      [req.params.boothId]
    );
    if (!booth) throw badRequest('Caseta no encontrada.');
    await closeOpenSessionsForScope({
      boothId: booth.id,
      stationId: booth.station_id,
      stationName: booth.station_name,
      boothCode: booth.code
    });
    await query(`UPDATE ${TABLES.assignments} SET is_active = 0 WHERE booth_id = ?`, [req.params.boothId]);
    await query(`DELETE FROM ${TABLES.booths} WHERE id = ?`, [req.params.boothId]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── ASIGNACIONES ─────────────────────────────────────────────────────────────

app.post('/api/assignments', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const { user_id, project_id, booth_id, station_id } = req.body;
    if (!user_id || !project_id) throw badRequest('Faltan campos obligatorios.');
    const [targetUser] = await query(`SELECT role FROM ${TABLES.users} WHERE id = ? LIMIT 1`, [user_id]);
    if (!targetUser) throw badRequest('Usuario no encontrado.');

    if (station_id && !booth_id) {
      await assertProjectAccess(req.authUser, project_id, { stationId: station_id });
      if ((ROLE_LEVEL[req.authUser.role] || 0) < ROLE_LEVEL['director']) throw forbidden('Solo directores pueden asignar personal a peajes.');
      if (targetUser?.role === 'registrador') {
        // Pool de peaje: solo desactivar asignación previa de este usuario en esta estación
        await query(
          `UPDATE ${TABLES.assignments}
           SET is_active = 0
           WHERE user_id = ? AND project_id = ? AND booth_id IS NULL AND is_active = 1`,
          [user_id, project_id]
        );
      } else {
        // Coordinador: desactivar coordinador anterior de esta estación
        await query(
          `UPDATE ${TABLES.assignments}
           SET is_active = 0
           WHERE project_id = ? AND station_id = ? AND booth_id IS NULL AND is_active = 1`,
          [project_id, station_id]
        );
      }
      const poolResult = await query(
        `INSERT INTO ${TABLES.assignments} (user_id, project_id, station_id, booth_id, assigned_by, is_active)
         VALUES (?, ?, ?, NULL, ?, 1)`,
        [user_id, project_id, station_id, req.authUser.user_id]
      );
      return res.json({ ok: true, assignmentId: poolResult.insertId });
    } else {
      // Asignar a caseta: solo desactivar asignaciones previas de caseta (conservar asignación de pool)
    }

    const [boothRow] = await query(`SELECT id, station_id FROM ${TABLES.booths} WHERE id = ? LIMIT 1`, [booth_id]);
    if (!boothRow) throw badRequest('La caseta indicada no existe.');
    await assertProjectAccess(req.authUser, project_id, { stationId: boothRow.station_id });
    if (targetUser.role !== 'registrador') throw badRequest('Solo se puede asignar casetas a registradores.');
    if (req.authUser.role === 'coordinador') {
      const presenceState = await getPresenceStateForUserProject(user_id, project_id);
      if (presenceState === 'offline') {
        throw forbidden('El coordinador solo puede asignar casetas a registradores conectados.');
      }
    }

    const existingSame = await query(
      `SELECT id FROM ${TABLES.assignments}
       WHERE user_id = ? AND project_id = ? AND booth_id = ? AND is_active = 1
       LIMIT 1`,
      [user_id, project_id, booth_id]
    );
    if (existingSame.length) return res.json({ ok: true, assignmentId: existingSame[0].id, reused: true });

    const poolRows = await query(
      `SELECT id FROM ${TABLES.assignments}
       WHERE user_id = ? AND project_id = ? AND station_id = ? AND booth_id IS NULL AND is_active = 1
       LIMIT 1`,
      [user_id, project_id, boothRow.station_id]
    );
    if (!poolRows.length) {
      if ((ROLE_LEVEL[req.authUser.role] || 0) < ROLE_LEVEL['director']) {
        throw forbidden('El usuario debe pertenecer al pool del peaje antes de asignarlo a una caseta.');
      }
      await query(
        `INSERT INTO ${TABLES.assignments} (user_id, project_id, station_id, booth_id, assigned_by, is_active)
         VALUES (?, ?, ?, NULL, ?, 1)`,
        [user_id, project_id, boothRow.station_id, req.authUser.user_id]
      );
    }

    const [projectRow] = await query(
      `SELECT COALESCE(max_booths_per_operator, 2) AS max_booths_per_operator FROM ${TABLES.projects} WHERE id = ? LIMIT 1`,
      [project_id]
    );
    const [activeBoothCount] = await query(
      `SELECT COUNT(DISTINCT booth_id) AS total
       FROM ${TABLES.assignments}
       WHERE user_id = ? AND project_id = ? AND booth_id IS NOT NULL AND is_active = 1`,
      [user_id, project_id]
    );
    const maxBooths = Number(projectRow?.max_booths_per_operator || 2);
    if (Number(activeBoothCount?.total || 0) >= maxBooths) {
      throw badRequest(`El usuario ya alcanzó el límite de ${maxBooths} caseta(s) activas para este proyecto.`);
    }

    await query(
      `UPDATE ${TABLES.assignments}
       SET is_active = 0
       WHERE project_id = ? AND booth_id = ? AND is_active = 1`,
      [project_id, booth_id]
    );

    const result = await query(
      `INSERT INTO ${TABLES.assignments} (user_id, project_id, station_id, booth_id, assigned_by, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
      [user_id, project_id, boothRow.station_id, booth_id, req.authUser.user_id]
    );
    res.json({ ok: true, assignmentId: result.insertId });
  } catch (error) { next(error); }
});

app.delete('/api/assignments/:id', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const rows = await query(
      `SELECT id, project_id, station_id
       FROM ${TABLES.assignments}
       WHERE id = ?
       LIMIT 1`,
      [req.params.id]
    );
    if (!rows.length) throw badRequest('Asignacion no encontrada.');
    await assertProjectAccess(req.authUser, rows[0].project_id, { stationId: rows[0].station_id });
    await query(`UPDATE ${TABLES.assignments} SET is_active = 0 WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// Usuarios disponibles para asignar (filtrado por ?role=)
app.get('/api/projects/:projectId/available-users', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    await assertProjectAccess(req.authUser, req.params.projectId);
    const roleFilter = req.query.role === 'coordinador' ? "u.role = 'coordinador'" : "u.role = 'registrador'";
    const rows = await query(
      `SELECT u.id, u.full_name, u.username, u.role,
              (SELECT a.id FROM ${TABLES.assignments} a
               WHERE a.user_id = u.id AND a.project_id = ? AND a.is_active = 1
               ORDER BY a.booth_id IS NULL ASC, a.created_at DESC LIMIT 1) AS assignment_id,
              (SELECT COUNT(DISTINCT a.booth_id) FROM ${TABLES.assignments} a
               WHERE a.user_id = u.id AND a.project_id = ? AND a.is_active = 1 AND a.booth_id IS NOT NULL) AS active_booths,
              (SELECT GROUP_CONCAT(tb.code ORDER BY tb.code SEPARATOR ', ')
               FROM ${TABLES.assignments} a
               INNER JOIN ${TABLES.booths} tb ON tb.id = a.booth_id
               WHERE a.user_id = u.id AND a.project_id = ? AND a.is_active = 1 AND a.booth_id IS NOT NULL) AS booth_codes,
              (SELECT a.station_id FROM ${TABLES.assignments} a
               WHERE a.user_id = u.id AND a.project_id = ? AND a.is_active = 1 AND a.booth_id IS NULL LIMIT 1) AS station_id
       FROM ${TABLES.users} u
       WHERE ${roleFilter} AND u.is_active = 1
      ORDER BY u.full_name`,
      [req.params.projectId, req.params.projectId, req.params.projectId, req.params.projectId]
    );
    const presenceRows = await query(
      `SELECT user_id, last_heartbeat_at
       FROM ${TABLES.presence}
       WHERE project_id = ?`,
      [req.params.projectId]
    );
    const presenceIndex = new Map();
    for (const row of presenceRows) {
      const current = presenceIndex.get(Number(row.user_id));
      if (!current || new Date(row.last_heartbeat_at).getTime() > new Date(current.last_heartbeat_at).getTime()) {
        presenceIndex.set(Number(row.user_id), row);
      }
    }
    const users = rows.map((row) => {
      const lastPresence = presenceIndex.get(Number(row.id));
      let presence_state = 'offline';
      if (lastPresence?.last_heartbeat_at) {
        const seconds = Math.max(0, Math.round((Date.now() - new Date(lastPresence.last_heartbeat_at).getTime()) / 1000));
        presence_state = seconds <= 45 ? 'online' : seconds <= 120 ? 'idle' : 'offline';
      }
      return { ...row, presence_state };
    });
    res.json({ ok: true, users });
  } catch (error) { next(error); }
});

app.post('/api/presence/heartbeat', authenticateRequest, async (req, res, next) => {
  try {
    const deviceId = String(req.body.deviceId || '').trim();
    if (!deviceId) throw badRequest('Falta deviceId.');
    if (req.body.projectId) {
      await assertProjectAccess(req.authUser, req.body.projectId, { stationId: req.body.stationId || null });
    }
    await query(
      `INSERT INTO ${TABLES.presence}
       (user_id, device_id, project_id, station_id, session_id, current_mode, network_status, context_json, last_heartbeat_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
       project_id = VALUES(project_id),
       station_id = VALUES(station_id),
       session_id = VALUES(session_id),
       current_mode = VALUES(current_mode),
       network_status = VALUES(network_status),
       context_json = VALUES(context_json),
       last_heartbeat_at = NOW()`,
      [
        req.authUser.user_id,
        deviceId,
        req.body.projectId || null,
        req.body.stationId || null,
        req.body.sessionId || null,
        String(req.body.currentMode || 'active'),
        String(req.body.networkStatus || 'online'),
        JSON.stringify(req.body.context || {})
      ]
    );
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.get('/api/projects/:projectId/presence', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const access = await assertProjectAccess(req.authUser, req.params.projectId);
    const managedStationIds = (access.managedStationIds || []).filter(Boolean);
    const stationFilter = req.authUser.role === 'coordinador'
      ? ` AND pr.station_id IN (${managedStationIds.map(() => '?').join(', ')})`
      : '';
    const rows = await query(
      `SELECT pr.user_id, pr.device_id, pr.project_id, pr.station_id, pr.session_id, pr.current_mode, pr.network_status,
              pr.last_heartbeat_at, u.full_name, u.username, u.role, ts.name AS station_name
       FROM ${TABLES.presence} pr
       INNER JOIN ${TABLES.users} u ON u.id = pr.user_id
       LEFT JOIN ${TABLES.stations} ts ON ts.id = pr.station_id
       WHERE pr.project_id = ?
       ${stationFilter}
       ORDER BY pr.last_heartbeat_at DESC`,
      [req.params.projectId, ...managedStationIds]
    );
    const presence = rows.map((row) => {
      const seconds = Math.max(0, Math.round((Date.now() - new Date(row.last_heartbeat_at).getTime()) / 1000));
      const state = seconds <= 45 ? 'online' : seconds <= 120 ? 'idle' : 'offline';
      return { ...row, seconds_since_heartbeat: seconds, presence_state: state };
    });
    res.json({ ok: true, presence });
  } catch (error) { next(error); }
});

// ─── ALERTAS DE PERSONAL ──────────────────────────────────────────────────────

app.get('/api/alerts/workers', authenticateRequest, requireMinRole('director'), async (_req, res, next) => {
  try {
    // Detectar usuarios asignados a 2+ casetas activas simultáneamente
    const doubleAssigned = await query(
      `SELECT u.id, u.full_name, u.username,
              COUNT(DISTINCT a.booth_id) AS active_booths,
              GROUP_CONCAT(CONCAT(ts.name,' C',tb.code) SEPARATOR ', ') AS booths_detail
       FROM ${TABLES.assignments} a
       INNER JOIN ${TABLES.users} u ON u.id = a.user_id
       INNER JOIN ${TABLES.booths} tb ON tb.id = a.booth_id
       INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
       WHERE a.is_active = 1 AND a.booth_id IS NOT NULL
       GROUP BY u.id HAVING active_booths > 1`
    );

    const overloadedOperators = await query(
      `SELECT u.id, u.full_name, u.username, p.name AS project_name,
              COUNT(DISTINCT a.booth_id) AS active_booths,
              COALESCE(p.max_booths_per_operator, 2) AS max_allowed,
              GROUP_CONCAT(CONCAT(ts.name,' C',tb.code) SEPARATOR ', ') AS booths_detail
       FROM ${TABLES.assignments} a
       INNER JOIN ${TABLES.users} u ON u.id = a.user_id
       INNER JOIN ${TABLES.projects} p ON p.id = a.project_id
       INNER JOIN ${TABLES.booths} tb ON tb.id = a.booth_id
       INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
       WHERE a.is_active = 1 AND a.booth_id IS NOT NULL
       GROUP BY u.id, p.id
       HAVING active_booths > max_allowed`
    );

    // Detectar sesiones abiertas de ayer o antes (turno sin cerrar)
    const staleSessions = await query(
      `SELECT s.id AS session_id, s.operation_date, s.created_at,
              COALESCE(u.full_name, p.operator_name) AS operator_name, p.toll_name, p.booth_number,
              DATEDIFF(NOW(), s.operation_date) AS days_open
       FROM ${TABLES.sessions} s
       INNER JOIN ${TABLES.profiles} p ON p.session_id = s.id AND p.profile_index = 0
       LEFT JOIN ${TABLES.users} u ON u.id = s.owner_user_id
       WHERE s.status = 'open' AND s.operation_date < CURDATE()
       ORDER BY s.operation_date ASC`
    );

    // Detectar operadores con registros en turnos consecutivos (mismo día, diferente sesión)
    const consecutiveShifts = await query(
      `SELECT COALESCE(u.full_name, r.operator_name) AS operator_name,
              r.operation_date, COUNT(DISTINCT r.session_id) AS sessions_count,
              MIN(r.passed_at) AS first_record, MAX(r.passed_at) AS last_record
       FROM ${TABLES.records} r
       LEFT JOIN ${TABLES.sessions} s ON s.id = r.session_id
       LEFT JOIN ${TABLES.users} u ON u.id = COALESCE(r.owner_user_id, s.owner_user_id)
       WHERE r.operation_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
       GROUP BY COALESCE(r.owner_user_id, s.owner_user_id, CONCAT('legacy:', LOWER(TRIM(r.operator_name)))),
                COALESCE(u.full_name, r.operator_name), r.operation_date
       HAVING sessions_count > 1`
    );

    // Actividad hoy por usuario
    const todayActivity = await query(
      `SELECT COALESCE(u.full_name, r.operator_name) AS operator_name, COUNT(*) AS records_today,
              MIN(r.passed_at) AS first_time, MAX(r.passed_at) AS last_time,
              COUNT(DISTINCT COALESCE(r.booth_id, CONCAT('legacy:', r.booth_number))) AS booths_used,
              GROUP_CONCAT(DISTINCT COALESCE(ts.name, r.toll_name) SEPARATOR ', ') AS toll_names
       FROM ${TABLES.records} r
       LEFT JOIN ${TABLES.sessions} s ON s.id = r.session_id
       LEFT JOIN ${TABLES.users} u ON u.id = COALESCE(r.owner_user_id, s.owner_user_id)
       LEFT JOIN ${TABLES.booths} tb ON tb.id = r.booth_id
       LEFT JOIN ${TABLES.stations} ts ON ts.id = COALESCE(r.station_id, tb.station_id)
       WHERE r.operation_date = CURDATE()
       GROUP BY COALESCE(r.owner_user_id, s.owner_user_id, CONCAT('legacy:', LOWER(TRIM(r.operator_name)))),
                COALESCE(u.full_name, r.operator_name)
       ORDER BY records_today DESC`
    );

    res.json({
      ok: true,
      alerts: {
        overloadedOperators,
        doubleAssigned,
        staleSessions,
        consecutiveShifts,
        todayActivity
      }
    });
  } catch (error) { next(error); }
});

// ─── DASHBOARD DIRECTOR ───────────────────────────────────────────────────────

app.get('/api/dashboard/director', authenticateRequest, requireMinRole('director'), async (_req, res, next) => {
  try {
    const projectStats = await query(
      `SELECT p.id, p.name, p.status, p.start_date, p.end_date, p.daily_start_time, p.daily_end_time,
              p.concession_id, c.name AS concession_name,
              COUNT(DISTINCT r.id) AS total_records,
              COUNT(DISTINCT CASE WHEN DATE(r.created_at) = CURDATE() THEN r.id END) AS records_today,
              COUNT(DISTINCT tb.id) AS total_booths,
              COUNT(DISTINCT CASE WHEN a.is_active = 1 THEN a.booth_id END) AS staffed_booths,
              COUNT(DISTINCT CASE WHEN a.is_active = 1 THEN a.user_id END) AS active_staff
       FROM ${TABLES.projects} p
       LEFT JOIN ${TABLES.concessions} c ON c.id = p.concession_id
       LEFT JOIN ${TABLES.projectSites} ps ON ps.project_id = p.id AND ps.is_active = 1
       LEFT JOIN ${TABLES.stations} ts ON ts.id = ps.station_id
       LEFT JOIN ${TABLES.booths} tb ON tb.station_id = ts.id
       LEFT JOIN ${TABLES.assignments} a ON a.project_id = p.id
       LEFT JOIN ${TABLES.records} r ON (r.project_id = p.id OR (r.project_id IS NULL AND r.toll_name = ts.name))
       GROUP BY p.id ORDER BY p.start_date DESC`
    );

    const weeklyTrend = await query(
      `SELECT operation_date, COUNT(*) AS records
       FROM ${TABLES.records}
       WHERE operation_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
       GROUP BY operation_date ORDER BY operation_date ASC`
    );

    const vehicleTypes = await query(
      `SELECT vehicle_type, COUNT(*) AS count
       FROM ${TABLES.records}
       WHERE operation_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
       GROUP BY vehicle_type ORDER BY count DESC`
    );

    res.json({ ok: true, projectStats, weeklyTrend, vehicleTypes });
  } catch (error) { next(error); }
});

// ─── DASHBOARD COORDINADOR ────────────────────────────────────────────────────

app.get('/api/dashboard/coordinator/:projectId', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const access = await assertProjectAccess(req.authUser, req.params.projectId);
    let stations = await getProjectStations(access.projectId);
    if (req.authUser.role === 'coordinador') {
      const allowedStationIds = new Set((access.managedStationIds || []).map((id) => Number(id)));
      stations = stations.filter((station) => allowedStationIds.has(Number(station.id)));
    }

    const projectInfo = await query(`SELECT * FROM ${TABLES.projects} WHERE id = ? LIMIT 1`, [req.params.projectId]);

    res.json({ ok: true, project: projectInfo[0] || null, stations });
  } catch (error) { next(error); }
});

// ─── CIERRE DE TURNO (solo coordinadores y superiores) ───────────────────────

app.post('/api/sessions/:id/close', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    await assertSessionAccess(req.authUser, req.params.id, { allowRegistradorOwn: false });
    await query(`UPDATE ${TABLES.sessions} SET status = 'closed' WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.post('/api/sessions/close-bulk', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const ids = Array.isArray(req.body.ids) ? req.body.ids.map((id) => String(id).trim()).filter(Boolean) : [];
    if (ids.length) {
      let closed = 0;
      for (const id of ids) {
        try {
          await assertSessionAccess(req.authUser, id, { allowRegistradorOwn: false });
          const result = await query(`UPDATE ${TABLES.sessions} SET status = 'closed' WHERE id = ? AND status <> 'closed'`, [id]);
          closed += Number(result.affectedRows || 0);
        } catch (error) {
          if (![400, 403].includes(Number(error?.status || 0))) throw error;
        }
      }
      return res.json({ ok: true, closed, scope: 'selected' });
    }
    if (req.authUser.role === 'coordinador') {
      const access = await assertProjectAccess(req.authUser, req.body.projectId);
      const managedStationIds = (access.managedStationIds || []).filter(Boolean);
      if (!managedStationIds.length) return res.json({ ok: true, closed: 0, scope: 'project' });
      const result = await query(
        `UPDATE ${TABLES.sessions} s
         LEFT JOIN ${TABLES.profiles} p ON p.session_id = s.id AND p.profile_index = 0
         SET s.status = 'closed'
         WHERE s.status = 'open'
           AND s.project_id = ?
           AND COALESCE(s.station_id, p.station_id) IN (${managedStationIds.map(() => '?').join(', ')})`,
        [access.projectId, ...managedStationIds]
      );
      return res.json({ ok: true, scope: 'project', projectId: access.projectId, closed: Number(result.affectedRows || 0) });
    }
    const result = await query(`UPDATE ${TABLES.sessions} SET status = 'closed' WHERE status = 'open'`);
    res.json({ ok: true, scope: 'all_open', closed: Number(result.affectedRows || 0) });
  } catch (error) { next(error); }
});

// ─── SESIONES ─────────────────────────────────────────────────────────────────

// Listar sesiones abiertas (para cerrar turno desde el panel)
app.get('/api/sessions/open', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const requestedProjectId = parseOptionalInt(req.query.projectId);
    if (requestedProjectId && req.authUser.role === 'coordinador') {
      await assertProjectAccess(req.authUser, requestedProjectId);
    }
    const filters = [`s.status = 'open'`];
    const params = [];
    if (requestedProjectId) {
      filters.push(`s.project_id = ?`);
      params.push(requestedProjectId);
    }
    if (req.authUser.role === 'coordinador') {
      const managedStations = await getCoordinatorManagedStations(req.authUser.user_id, requestedProjectId);
      if (!managedStations.length) return res.json({ ok: true, sessions: [] });
      const scope = managedStations.map(() => `(s.project_id = ? AND COALESCE(s.station_id, p.station_id) = ?)`);
      filters.push(`(${scope.join(' OR ')})`);
      managedStations.forEach((item) => {
        params.push(item.projectId, item.stationId);
      });
    }
    const sessions = await query(
      `SELECT s.id, s.operation_date, s.status,
              s.project_id, COALESCE(s.station_id, p.station_id) AS station_id,
              p.operator_name, p.toll_name, p.booth_number, p.direction
       FROM ${TABLES.sessions} s
       INNER JOIN ${TABLES.profiles} p ON p.session_id = s.id AND p.profile_index = 0
       WHERE ${filters.join(' AND ')}
       ORDER BY s.operation_date DESC, p.toll_name ASC`,
      params
    );
    res.json({ ok: true, sessions });
  } catch (error) { next(error); }
});

app.post('/api/sessions/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const session = mapSessionPayload(req.body);
    const existingSession = await getSessionContext(session.id);
    if (
      existingSession &&
      existingSession.owner_user_id &&
      Number(existingSession.owner_user_id) !== Number(req.authUser.user_id) &&
      !['admin', 'director'].includes(req.authUser.role)
    ) {
      throw forbidden('No puedes modificar un turno que pertenece a otro usuario.');
    }
    if (session.projectId && req.authUser.role !== 'registrador') {
      await assertProjectAccess(req.authUser, session.projectId, { stationId: session.stationId });
    }
    const ownerUserId = Number(existingSession?.owner_user_id || req.authUser.user_id);
    await withTransaction(async (conn) => {
      await conn.execute(
        `INSERT INTO ${TABLES.sessions} (id,operation_date,is_multi,active_profile_index,status,owner_user_id,project_id,station_id)
         VALUES (?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE
         operation_date=VALUES(operation_date),is_multi=VALUES(is_multi),
         active_profile_index=VALUES(active_profile_index),status=VALUES(status),
         owner_user_id=COALESCE(owner_user_id, VALUES(owner_user_id)),
         project_id=VALUES(project_id),station_id=VALUES(station_id)`,
        [session.id, session.operationDate, session.multi ? 1 : 0, session.activeIndex, session.status, ownerUserId, session.projectId, session.stationId]
      );
      await conn.execute(`DELETE FROM ${TABLES.profiles} WHERE session_id = ?`, [session.id]);
      for (const p of session.profiles) {
        await conn.execute(
          `INSERT INTO ${TABLES.profiles} (session_id,profile_index,toll_name,booth_number,operator_name,direction,project_id,station_id,booth_id)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          [session.id, p.profileIndex, p.tollName, p.boothNumber, p.operatorName, p.direction, p.projectId, p.stationId, p.boothId]
        );
      }
    });
    res.json({ ok: true, sessionId: session.id });
  } catch (error) { next(error); }
});

app.get('/api/sessions/:id', authenticateRequest, async (req, res, next) => {
  try {
    const session = await assertSessionAccess(req.authUser, req.params.id);
    const profiles = await query(
      `SELECT profile_index,toll_name,booth_number,operator_name,direction,project_id,station_id,booth_id FROM ${TABLES.profiles}
       WHERE session_id = ? ORDER BY profile_index ASC`, [req.params.id]
    );
    res.json({ ok: true, session, profiles });
  } catch (error) { next(error); }
});

// ─── REGISTROS ────────────────────────────────────────────────────────────────

app.post('/api/records/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const r = mapRecordPayload(req.body);
    const session = await assertSessionAccess(req.authUser, r.sessionId);
    const ownerUserId = Number(session.owner_user_id || req.authUser.user_id);
    const recordProjectId = parseOptionalInt(session.project_id || r.projectId);
    const recordStationId = parseOptionalInt(session.station_id || r.stationId);
    const recordBoothId = parseOptionalInt(r.boothId);
    await query(
      `INSERT INTO ${TABLES.records}
       (id,session_id,operation_date,toll_name,booth_number,direction,operator_name,
        passed_at,main_plate,vehicle_type,main_axles,secondary_plate,secondary_axles,total_axles,sync_status,is_fugitive,
        owner_user_id,project_id,station_id,booth_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
       session_id=VALUES(session_id),operation_date=VALUES(operation_date),toll_name=VALUES(toll_name),
       booth_number=VALUES(booth_number),direction=VALUES(direction),operator_name=VALUES(operator_name),
       passed_at=VALUES(passed_at),main_plate=VALUES(main_plate),vehicle_type=VALUES(vehicle_type),
       main_axles=VALUES(main_axles),secondary_plate=VALUES(secondary_plate),
       secondary_axles=VALUES(secondary_axles),total_axles=VALUES(total_axles),sync_status=VALUES(sync_status),
       is_fugitive=VALUES(is_fugitive),owner_user_id=VALUES(owner_user_id),
       project_id=VALUES(project_id),station_id=VALUES(station_id),booth_id=VALUES(booth_id)`,
      [r.id,r.sessionId,r.operationDate,r.tollName,r.boothNumber,r.direction,r.operatorName,
       r.passedAt,r.mainPlate,r.vehicleType,r.mainAxles,r.secondaryPlate,r.secondaryAxles,r.totalAxles,r.syncStatus,r.isFugitive,
       ownerUserId, recordProjectId, recordStationId, recordBoothId]
    );
    res.json({ ok: true, recordId: r.id });
  } catch (error) { next(error); }
});

app.get('/api/records', authenticateRequest, async (req, res, next) => {
  try {
    const filters = []; const params = [];
    const requestedProjectId = parseOptionalInt(req.query.projectId);
    if (req.authUser.role === 'registrador') {
      filters.push('s.owner_user_id = ?');
      params.push(req.authUser.user_id);
    } else if (req.authUser.role === 'coordinador') {
      if (requestedProjectId) await assertProjectAccess(req.authUser, requestedProjectId);
      const managedStations = await getCoordinatorManagedStations(req.authUser.user_id, requestedProjectId);
      if (!managedStations.length) return res.json({ ok: true, rows: [] });
      const scope = managedStations.map(() => `(s.project_id = ? AND COALESCE(s.station_id, sp.station_id) = ?)`);
      filters.push(`(${scope.join(' OR ')})`);
      managedStations.forEach((item) => {
        params.push(item.projectId, item.stationId);
      });
    } else if (requestedProjectId) {
      filters.push('s.project_id = ?');
      params.push(requestedProjectId);
    }
    if (req.query.sessionId)     { filters.push('r.session_id = ?');     params.push(String(req.query.sessionId)); }
    if (req.query.operationDate) { filters.push('r.operation_date = ?'); params.push(String(req.query.operationDate)); }
    if (req.query.tollName)      { filters.push('r.toll_name = ?');      params.push(String(req.query.tollName)); }
    if (req.query.boothNumber)   { filters.push('r.booth_number = ?');   params.push(String(req.query.boothNumber)); }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const rows = await query(
      `SELECT r.*
       FROM ${TABLES.records} r
       INNER JOIN ${TABLES.sessions} s ON s.id = r.session_id
       LEFT JOIN ${TABLES.profiles} sp ON sp.session_id = s.id AND sp.profile_index = 0
       ${where}
       ORDER BY r.operation_date DESC, r.passed_at DESC, r.created_at DESC`,
      params
    );
    res.json({ ok: true, rows });
  } catch (error) { next(error); }
});

app.delete('/api/records/:id', authenticateRequest, async (req, res, next) => {
  try {
    const rows = await query(
      `SELECT id, session_id
       FROM ${TABLES.records}
       WHERE id = ?
       LIMIT 1`,
      [req.params.id]
    );
    if (!rows.length) throw badRequest('Registro no encontrado.');
    await assertSessionAccess(req.authUser, rows[0].session_id);
    await query(`DELETE FROM ${TABLES.records} WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── CATCH-ALL FRONTEND ───────────────────────────────────────────────────────

app.get(/^\/(?!api).*/, (_req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

app.use((error, _req, res, _next) => {
  const status = error.status || 500;
  res.status(status).json({ ok: false, error: error.message || 'Error interno.' });
});

// ─── MIGRACIONES + SEED ───────────────────────────────────────────────────────

async function runMigrations() {
  console.log('Ejecutando migraciones...');

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.users} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      username VARCHAR(80) NOT NULL,
      full_name VARCHAR(120) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','director','coordinador','registrador') NOT NULL DEFAULT 'registrador',
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_auth_users_username (username)
    )
  `);

  // Agregar columna role si ya existe la tabla sin ella
  try {
    await query(`ALTER TABLE ${TABLES.users} ADD COLUMN role ENUM('admin','director','coordinador','registrador') NOT NULL DEFAULT 'registrador' AFTER password_hash`);
  } catch (_) {}
  // Agregar columnas de horario a estaciones si ya existe la tabla sin ellas
  try {
    await query(`ALTER TABLE ${TABLES.stations} ADD COLUMN daily_start_time TIME NULL AFTER location`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.stations} ADD COLUMN daily_end_time TIME NULL AFTER daily_start_time`);
  } catch (_) {}
  // Agregar station_id a asignaciones si ya existe la tabla sin ella
  try {
    await query(`ALTER TABLE ${TABLES.assignments} ADD COLUMN station_id INT UNSIGNED NULL AFTER project_id`);
  } catch (_) {}
  // Asegurar que admin tenga rol admin
  await query(`UPDATE ${TABLES.users} SET role = 'admin' WHERE username = 'admin'`);

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
    CREATE TABLE IF NOT EXISTS ${TABLES.concessions} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      name VARCHAR(160) NOT NULL,
      status ENUM('activa','inactiva') NOT NULL DEFAULT 'activa',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_concessions_name (name)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.projects} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      name VARCHAR(120) NOT NULL,
      description TEXT NULL,
      status ENUM('activo','pausado','cerrado') NOT NULL DEFAULT 'activo',
      start_date DATE NOT NULL,
      end_date DATE NULL,
      concession_id INT UNSIGNED NULL,
      daily_start_time TIME NULL COMMENT 'Hora inicio registro cada día',
      daily_end_time TIME NULL COMMENT 'Hora fin registro cada día',
      max_booths_per_operator INT NOT NULL DEFAULT 2,
      created_by BIGINT UNSIGNED NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.stations} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      project_id INT UNSIGNED NULL,
      concession_id INT UNSIGNED NULL,
      name VARCHAR(120) NOT NULL,
      location VARCHAR(200) NULL,
      daily_start_time TIME NULL COMMENT 'Hora inicio registro en este peaje',
      daily_end_time TIME NULL COMMENT 'Hora fin registro en este peaje',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.booths} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      station_id INT UNSIGNED NOT NULL,
      code VARCHAR(30) NOT NULL,
      directions VARCHAR(200) NOT NULL DEFAULT '',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      CONSTRAINT fk_cidatt_booths_station FOREIGN KEY (station_id) REFERENCES ${TABLES.stations} (id) ON DELETE CASCADE
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.projectSites} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      project_id INT UNSIGNED NOT NULL,
      station_id INT UNSIGNED NOT NULL,
      linked_by BIGINT UNSIGNED NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_project_sites_project_station (project_id, station_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.assignments} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      project_id INT UNSIGNED NOT NULL,
      station_id INT UNSIGNED NULL,
      booth_id INT UNSIGNED NULL,
      assigned_by BIGINT UNSIGNED NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_cidatt_assignments_user (user_id),
      KEY idx_cidatt_assignments_project (project_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.sessions} (
      id CHAR(36) NOT NULL,
      operation_date DATE NOT NULL,
      is_multi TINYINT(1) NOT NULL DEFAULT 0,
      active_profile_index INT NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      owner_user_id BIGINT UNSIGNED NULL,
      project_id INT UNSIGNED NULL,
      station_id INT UNSIGNED NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_cidatt_shift_sessions_operation_date (operation_date),
      KEY idx_cidatt_shift_sessions_scope (project_id, station_id, status)
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
      project_id INT UNSIGNED NULL,
      station_id INT UNSIGNED NULL,
      booth_id INT UNSIGNED NULL,
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
      is_fugitive TINYINT(1) NOT NULL DEFAULT 0,
      owner_user_id BIGINT UNSIGNED NULL,
      project_id INT UNSIGNED NULL,
      station_id INT UNSIGNED NULL,
      booth_id INT UNSIGNED NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_cidatt_vehicle_records_session_id (session_id),
      KEY idx_cidatt_vehicle_records_operation_date (operation_date),
      KEY idx_cidatt_vehicle_records_main_plate (main_plate),
      KEY idx_cidatt_vehicle_records_scope (project_id, station_id, booth_id),
      CONSTRAINT fk_cidatt_vehicle_records_session FOREIGN KEY (session_id) REFERENCES ${TABLES.sessions} (id) ON DELETE CASCADE
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.presence} (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      device_id VARCHAR(120) NOT NULL,
      project_id INT UNSIGNED NULL,
      station_id INT UNSIGNED NULL,
      session_id CHAR(36) NULL,
      current_mode VARCHAR(40) NOT NULL DEFAULT 'active',
      network_status VARCHAR(20) NOT NULL DEFAULT 'online',
      context_json JSON NULL,
      last_heartbeat_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_cidatt_presence_user_device (user_id, device_id)
    )
  `);

  // ─── SEED usuarios de prueba ──────────────────────────────────────────────
  try {
    await query(`ALTER TABLE ${TABLES.projects} ADD COLUMN max_booths_per_operator INT NOT NULL DEFAULT 2 AFTER daily_end_time`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.projects} ADD COLUMN concession_id INT UNSIGNED NULL AFTER end_date`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.stations} DROP FOREIGN KEY fk_cidatt_stations_project`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.stations} MODIFY COLUMN project_id INT UNSIGNED NULL`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.stations} ADD COLUMN concession_id INT UNSIGNED NULL AFTER project_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.records} ADD COLUMN is_fugitive TINYINT(1) NOT NULL DEFAULT 0 AFTER sync_status`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.sessions} ADD COLUMN owner_user_id BIGINT UNSIGNED NULL AFTER status`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.sessions} ADD COLUMN project_id INT UNSIGNED NULL AFTER owner_user_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.sessions} ADD COLUMN station_id INT UNSIGNED NULL AFTER project_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.profiles} ADD COLUMN project_id INT UNSIGNED NULL AFTER direction`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.profiles} ADD COLUMN station_id INT UNSIGNED NULL AFTER project_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.profiles} ADD COLUMN booth_id INT UNSIGNED NULL AFTER station_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.records} ADD COLUMN owner_user_id BIGINT UNSIGNED NULL AFTER is_fugitive`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.records} ADD COLUMN project_id INT UNSIGNED NULL AFTER owner_user_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.records} ADD COLUMN station_id INT UNSIGNED NULL AFTER project_id`);
  } catch (_) {}
  try {
    await query(`ALTER TABLE ${TABLES.records} ADD COLUMN booth_id INT UNSIGNED NULL AFTER station_id`);
  } catch (_) {}
  await query(`UPDATE ${TABLES.projects} SET max_booths_per_operator = 2 WHERE max_booths_per_operator IS NULL OR max_booths_per_operator > 2 OR max_booths_per_operator < 1`);

  const defaultConcessionId = await ensureDefaultConcession();
  await query(`UPDATE ${TABLES.stations} SET concession_id = COALESCE(concession_id, ?)`, [defaultConcessionId]);
  await query(`UPDATE ${TABLES.projects} SET concession_id = COALESCE(concession_id, ?)`, [defaultConcessionId]);
  await query(
    `INSERT IGNORE INTO ${TABLES.projectSites} (project_id, station_id, linked_by, is_active)
     SELECT project_id, id, NULL, 1
     FROM ${TABLES.stations}`
  );
  await query(`UPDATE ${TABLES.stations} SET project_id = NULL`);
  await query(
    `UPDATE ${TABLES.profiles} sp
     INNER JOIN ${TABLES.booths} tb ON tb.code = sp.booth_number
     INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id AND LOWER(TRIM(ts.name)) = LOWER(TRIM(sp.toll_name))
     SET sp.station_id = COALESCE(sp.station_id, ts.id),
         sp.booth_id = COALESCE(sp.booth_id, tb.id)
     WHERE sp.station_id IS NULL OR sp.booth_id IS NULL`
  );
  await query(
    `UPDATE ${TABLES.sessions} s
     INNER JOIN ${TABLES.profiles} sp ON sp.session_id = s.id AND sp.profile_index = 0
     LEFT JOIN ${TABLES.users} u ON LOWER(TRIM(u.full_name)) = LOWER(TRIM(sp.operator_name))
     SET s.owner_user_id = COALESCE(s.owner_user_id, u.id),
         s.project_id = COALESCE(s.project_id, sp.project_id),
         s.station_id = COALESCE(s.station_id, sp.station_id)
     WHERE s.owner_user_id IS NULL OR s.project_id IS NULL OR s.station_id IS NULL`
  );
  await query(
    `UPDATE ${TABLES.records} r
     INNER JOIN ${TABLES.sessions} s ON s.id = r.session_id
     SET r.owner_user_id = COALESCE(r.owner_user_id, s.owner_user_id),
         r.project_id = COALESCE(r.project_id, s.project_id),
         r.station_id = COALESCE(r.station_id, s.station_id)
     WHERE r.owner_user_id IS NULL OR r.project_id IS NULL OR r.station_id IS NULL`
  );
  await query(
    `UPDATE ${TABLES.records} r
     INNER JOIN ${TABLES.booths} tb ON tb.code = r.booth_number
     INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id AND LOWER(TRIM(ts.name)) = LOWER(TRIM(r.toll_name))
     SET r.station_id = COALESCE(r.station_id, ts.id),
         r.booth_id = COALESCE(r.booth_id, tb.id)
     WHERE r.station_id IS NULL OR r.booth_id IS NULL`
  );

  const seedUsers = [
    { username: 'admin',            full_name: 'Administrador CIDATT',  role: 'admin',        password: 'CIDATT2026!' },
    { username: 'director.test',    full_name: 'Director de Prueba',    role: 'director',     password: 'Director2026!' },
    { username: 'coord.test',       full_name: 'Coordinador de Prueba', role: 'coordinador',  password: 'Coord2026!' },
    { username: 'registrador.test', full_name: 'Registrador de Prueba', role: 'registrador',  password: 'Reg2026!' },
    { username: 'reg2.test',        full_name: 'Registrador 2 Prueba',  role: 'registrador',  password: 'Reg2026!' },
    { username: 'reg3.test',        full_name: 'Registrador 3 Prueba',  role: 'registrador',  password: 'Reg2026!' },
    { username: 'reg4.test',        full_name: 'Registrador 4 Prueba',  role: 'registrador',  password: 'Reg2026!' }
  ];

  for (const u of seedUsers) {
    const exists = await query(`SELECT id FROM ${TABLES.users} WHERE username = ? LIMIT 1`, [u.username]);
    if (!exists.length) {
      const hash = await bcrypt.hash(u.password, 12);
      await query(
        `INSERT INTO ${TABLES.users} (username, full_name, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)`,
        [u.username, u.full_name, hash, u.role]
      );
      console.log(`Usuario ${u.username} (${u.role}) creado.`);
    }
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
