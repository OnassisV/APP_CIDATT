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
  stations:    'cidatt_toll_stations',
  booths:      'cidatt_toll_booths',
  assignments: 'cidatt_user_assignments'
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
  return {
    id: String(body.id),
    operationDate: String(body.operationDate),
    multi: Boolean(body.multi),
    activeIndex: Number(body.activeIndex || 0),
    status: String(body.status || 'open'),
    profiles: body.profiles.map((p, i) => ({
      profileIndex: i,
      tollName: String(p.nombrePeaje || ''),
      boothNumber: String(p.numeroCaseta || ''),
      operatorName: String(p.operador || ''),
      direction: String(p.sentidoCirculacion || '')
    }))
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
    syncStatus: String(body.syncStatus || 'synced')
  };
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

    // Obtener asignacion activa del usuario (para registradores/coordinadores)
    const assignments = await query(
      `SELECT a.id, a.project_id, a.booth_id, p.name AS project_name,
              ts.name AS station_name, tb.code AS booth_code, tb.directions
       FROM ${TABLES.assignments} a
       LEFT JOIN ${TABLES.projects}  p  ON p.id = a.project_id
       LEFT JOIN ${TABLES.booths}    tb ON tb.id = a.booth_id
       LEFT JOIN ${TABLES.stations}  ts ON ts.id = tb.station_id
       WHERE a.user_id = ? AND a.is_active = 1 LIMIT 1`,
      [users[0].id]
    );

    res.json({
      ok: true, token: plainToken,
      user: {
        id: users[0].id, username: users[0].username,
        fullName: users[0].full_name, role: users[0].role
      },
      assignment: assignments[0] || null
    });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', authenticateRequest, async (req, res) => {
  const assignments = await query(
    `SELECT a.id, a.project_id, a.booth_id, p.name AS project_name,
            ts.name AS station_name, tb.code AS booth_code, tb.directions
     FROM ${TABLES.assignments} a
     LEFT JOIN ${TABLES.projects}  p  ON p.id = a.project_id
     LEFT JOIN ${TABLES.booths}    tb ON tb.id = a.booth_id
     LEFT JOIN ${TABLES.stations}  ts ON ts.id = tb.station_id
     WHERE a.user_id = ? AND a.is_active = 1 LIMIT 1`,
    [req.authUser.user_id]
  );
  res.json({
    ok: true,
    user: { id: req.authUser.user_id, username: req.authUser.username, fullName: req.authUser.full_name, role: req.authUser.role },
    assignment: assignments[0] || null
  });
});

// ─── USUARIOS (admin y director pueden gestionar) ─────────────────────────────

app.get('/api/users', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const myLevel = ROLE_LEVEL[req.authUser.role] || 0;
    // Solo puede ver usuarios de rol inferior al suyo
    const rows = await query(
      `SELECT id, username, full_name, role, is_active, created_at FROM ${TABLES.users} ORDER BY role, full_name`
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

// ─── PROYECTOS ────────────────────────────────────────────────────────────────

app.get('/api/projects', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    let rows;
    if (['admin', 'director'].includes(req.authUser.role)) {
      rows = await query(`SELECT * FROM ${TABLES.projects} ORDER BY start_date DESC`);
    } else {
      // Coordinador: solo sus proyectos asignados
      rows = await query(
        `SELECT DISTINCT p.* FROM ${TABLES.projects} p
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
         WHERE toll_name IN (
           SELECT ts.name FROM ${TABLES.stations} ts WHERE ts.project_id = ?
         )`,
        [p.id]
      );
      const [boothCounts] = await query(
        `SELECT COUNT(*) AS total_booths,
                SUM(CASE WHEN a.user_id IS NOT NULL AND a.is_active = 1 THEN 1 ELSE 0 END) AS staffed_booths
         FROM ${TABLES.booths} tb
         INNER JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
         LEFT JOIN ${TABLES.assignments} a ON a.booth_id = tb.id AND a.is_active = 1
         WHERE ts.project_id = ?`,
        [p.id]
      );
      p.total_records  = counts.total_records;
      p.total_sessions = counts.total_sessions;
      p.total_booths   = boothCounts.total_booths;
      p.staffed_booths = boothCounts.staffed_booths;
    }
    res.json({ ok: true, projects: rows });
  } catch (error) { next(error); }
});

app.post('/api/projects', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, description, start_date, end_date, daily_start_time, daily_end_time } = req.body;
    if (!name || !start_date) throw badRequest('Nombre y fecha de inicio son obligatorios.');
    const result = await query(
      `INSERT INTO ${TABLES.projects} (name, description, start_date, end_date, daily_start_time, daily_end_time, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [String(name).trim(), description || null, start_date, end_date || null,
       daily_start_time || null, daily_end_time || null, req.authUser.user_id]
    );
    res.json({ ok: true, projectId: result.insertId });
  } catch (error) { next(error); }
});

app.put('/api/projects/:id', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, description, start_date, end_date, daily_start_time, daily_end_time, status } = req.body;
    await query(
      `UPDATE ${TABLES.projects} SET name=COALESCE(?,name), description=COALESCE(?,description),
       start_date=COALESCE(?,start_date), end_date=COALESCE(?,end_date),
       daily_start_time=COALESCE(?,daily_start_time), daily_end_time=COALESCE(?,daily_end_time),
       status=COALESCE(?,status) WHERE id=?`,
      [name||null, description||null, start_date||null, end_date||null,
       daily_start_time||null, daily_end_time||null, status||null, req.params.id]
    );
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── ESTACIONES / CASETAS ─────────────────────────────────────────────────────

app.get('/api/projects/:projectId/stations', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const stations = await query(
      `SELECT ts.*, COUNT(tb.id) AS booth_count FROM ${TABLES.stations} ts
       LEFT JOIN ${TABLES.booths} tb ON tb.station_id = ts.id
       WHERE ts.project_id = ? GROUP BY ts.id ORDER BY ts.name`,
      [req.params.projectId]
    );
    for (const s of stations) {
      s.booths = await query(
        `SELECT tb.*, u.id AS assigned_user_id, u.full_name AS assigned_user_name, u.username AS assigned_username
         FROM ${TABLES.booths} tb
         LEFT JOIN ${TABLES.assignments} a ON a.booth_id = tb.id AND a.is_active = 1
         LEFT JOIN ${TABLES.users} u ON u.id = a.user_id
         WHERE tb.station_id = ? ORDER BY tb.code`,
        [s.id]
      );
    }
    res.json({ ok: true, stations });
  } catch (error) { next(error); }
});

app.post('/api/projects/:projectId/stations', authenticateRequest, requireMinRole('director'), async (req, res, next) => {
  try {
    const { name, location } = req.body;
    if (!name) throw badRequest('Nombre de estación requerido.');
    const result = await query(
      `INSERT INTO ${TABLES.stations} (project_id, name, location) VALUES (?, ?, ?)`,
      [req.params.projectId, String(name).trim(), location || null]
    );
    res.json({ ok: true, stationId: result.insertId });
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

// ─── ASIGNACIONES ─────────────────────────────────────────────────────────────

app.post('/api/assignments', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const { user_id, project_id, booth_id } = req.body;
    if (!user_id || !project_id) throw badRequest('Faltan campos obligatorios.');

    // Desactivar asignaciones previas del usuario en este proyecto
    await query(
      `UPDATE ${TABLES.assignments} SET is_active = 0 WHERE user_id = ? AND project_id = ?`,
      [user_id, project_id]
    );
    // Si booth_id es null = solo asignar a proyecto sin caseta específica
    const result = await query(
      `INSERT INTO ${TABLES.assignments} (user_id, project_id, booth_id, assigned_by, is_active)
       VALUES (?, ?, ?, ?, 1)`,
      [user_id, project_id, booth_id || null, req.authUser.user_id]
    );
    res.json({ ok: true, assignmentId: result.insertId });
  } catch (error) { next(error); }
});

app.delete('/api/assignments/:id', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    await query(`UPDATE ${TABLES.assignments} SET is_active = 0 WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// Usuarios disponibles para asignar (registradores y coordinadores del proyecto o sin asignar)
app.get('/api/projects/:projectId/available-users', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    const rows = await query(
      `SELECT u.id, u.full_name, u.username, u.role,
              a.id AS assignment_id, a.booth_id,
              tb.code AS booth_code, ts.name AS station_name
       FROM ${TABLES.users} u
       LEFT JOIN ${TABLES.assignments} a ON a.user_id = u.id AND a.project_id = ? AND a.is_active = 1
       LEFT JOIN ${TABLES.booths} tb ON tb.id = a.booth_id
       LEFT JOIN ${TABLES.stations} ts ON ts.id = tb.station_id
       WHERE u.role IN ('registrador','coordinador') AND u.is_active = 1
       ORDER BY u.role DESC, u.full_name`,
      [req.params.projectId]
    );
    res.json({ ok: true, users: rows });
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

    // Detectar sesiones abiertas de ayer o antes (turno sin cerrar)
    const staleSessions = await query(
      `SELECT s.id AS session_id, s.operation_date, s.created_at,
              p.operator_name, p.toll_name, p.booth_number,
              DATEDIFF(NOW(), s.operation_date) AS days_open
       FROM ${TABLES.sessions} s
       INNER JOIN ${TABLES.profiles} p ON p.session_id = s.id AND p.profile_index = 0
       WHERE s.status = 'open' AND s.operation_date < CURDATE()
       ORDER BY s.operation_date ASC`
    );

    // Detectar operadores con registros en turnos consecutivos (mismo día, diferente sesión)
    const consecutiveShifts = await query(
      `SELECT operator_name, operation_date, COUNT(DISTINCT session_id) AS sessions_count,
              MIN(passed_at) AS first_record, MAX(passed_at) AS last_record
       FROM ${TABLES.records}
       WHERE operation_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
       GROUP BY operator_name, operation_date
       HAVING sessions_count > 1`
    );

    // Actividad hoy por usuario
    const todayActivity = await query(
      `SELECT r.operator_name, COUNT(*) AS records_today,
              MIN(r.passed_at) AS first_time, MAX(r.passed_at) AS last_time,
              COUNT(DISTINCT r.booth_number) AS booths_used,
              GROUP_CONCAT(DISTINCT r.toll_name SEPARATOR ', ') AS toll_names
       FROM ${TABLES.records} r
       WHERE r.operation_date = CURDATE()
       GROUP BY r.operator_name ORDER BY records_today DESC`
    );

    res.json({
      ok: true,
      alerts: {
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
              COUNT(DISTINCT r.id) AS total_records,
              COUNT(DISTINCT CASE WHEN DATE(r.created_at) = CURDATE() THEN r.id END) AS records_today,
              COUNT(DISTINCT tb.id) AS total_booths,
              COUNT(DISTINCT CASE WHEN a.is_active = 1 THEN a.booth_id END) AS staffed_booths,
              COUNT(DISTINCT CASE WHEN a.is_active = 1 THEN a.user_id END) AS active_staff
       FROM ${TABLES.projects} p
       LEFT JOIN ${TABLES.stations} ts ON ts.project_id = p.id
       LEFT JOIN ${TABLES.booths} tb ON tb.station_id = ts.id
       LEFT JOIN ${TABLES.assignments} a ON a.project_id = p.id
       LEFT JOIN ${TABLES.records} r ON r.toll_name = ts.name
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
    const stations = await query(
      `SELECT ts.id, ts.name, ts.location FROM ${TABLES.stations} ts WHERE ts.project_id = ? ORDER BY ts.name`,
      [req.params.projectId]
    );
    for (const s of stations) {
      s.booths = await query(
        `SELECT tb.id, tb.code, tb.directions,
                u.id AS user_id, u.full_name, u.username, u.role,
                a.id AS assignment_id,
                (SELECT COUNT(*) FROM ${TABLES.records} r
                 WHERE r.booth_number = tb.code AND r.toll_name = ts.name AND r.operation_date = CURDATE()) AS records_today
         FROM ${TABLES.booths} tb
         INNER JOIN ${TABLES.stations} ts2 ON ts2.id = tb.station_id
         LEFT JOIN ${TABLES.assignments} a ON a.booth_id = tb.id AND a.is_active = 1
         LEFT JOIN ${TABLES.users} u ON u.id = a.user_id
         WHERE tb.station_id = ? ORDER BY tb.code`,
        [s.id]
      );
    }

    const projectInfo = await query(`SELECT * FROM ${TABLES.projects} WHERE id = ? LIMIT 1`, [req.params.projectId]);

    res.json({ ok: true, project: projectInfo[0] || null, stations });
  } catch (error) { next(error); }
});

// ─── CIERRE DE TURNO (solo coordinadores y superiores) ───────────────────────

app.post('/api/sessions/:id/close', authenticateRequest, requireMinRole('coordinador'), async (req, res, next) => {
  try {
    await query(`UPDATE ${TABLES.sessions} SET status = 'closed' WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// ─── SESIONES ─────────────────────────────────────────────────────────────────

// Listar sesiones abiertas (para cerrar turno desde el panel)
app.get('/api/sessions/open', authenticateRequest, requireMinRole('coordinador'), async (_req, res, next) => {
  try {
    const sessions = await query(
      `SELECT s.id, s.operation_date, s.status,
              p.operator_name, p.toll_name, p.booth_number, p.direction
       FROM ${TABLES.sessions} s
       INNER JOIN ${TABLES.profiles} p ON p.session_id = s.id AND p.profile_index = 0
       WHERE s.status = 'open'
       ORDER BY s.operation_date DESC, p.toll_name ASC`
    );
    res.json({ ok: true, sessions });
  } catch (error) { next(error); }
});

app.post('/api/sessions/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const session = mapSessionPayload(req.body);
    await withTransaction(async (conn) => {
      await conn.execute(
        `INSERT INTO ${TABLES.sessions} (id,operation_date,is_multi,active_profile_index,status)
         VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE
         operation_date=VALUES(operation_date),is_multi=VALUES(is_multi),
         active_profile_index=VALUES(active_profile_index),status=VALUES(status)`,
        [session.id, session.operationDate, session.multi?1:0, session.activeIndex, session.status]
      );
      await conn.execute(`DELETE FROM ${TABLES.profiles} WHERE session_id = ?`, [session.id]);
      for (const p of session.profiles) {
        await conn.execute(
          `INSERT INTO ${TABLES.profiles} (session_id,profile_index,toll_name,booth_number,operator_name,direction)
           VALUES (?,?,?,?,?,?)`,
          [session.id, p.profileIndex, p.tollName, p.boothNumber, p.operatorName, p.direction]
        );
      }
    });
    res.json({ ok: true, sessionId: session.id });
  } catch (error) { next(error); }
});

app.get('/api/sessions/:id', authenticateRequest, async (req, res, next) => {
  try {
    const sessions = await query(`SELECT * FROM ${TABLES.sessions} WHERE id = ?`, [req.params.id]);
    if (!sessions.length) return res.status(404).json({ ok: false, error: 'Sesion no encontrada.' });
    const profiles = await query(
      `SELECT profile_index,toll_name,booth_number,operator_name,direction FROM ${TABLES.profiles}
       WHERE session_id = ? ORDER BY profile_index ASC`, [req.params.id]
    );
    res.json({ ok: true, session: sessions[0], profiles });
  } catch (error) { next(error); }
});

// ─── REGISTROS ────────────────────────────────────────────────────────────────

app.post('/api/records/upsert', authenticateRequest, async (req, res, next) => {
  try {
    const r = mapRecordPayload(req.body);
    await query(
      `INSERT INTO ${TABLES.records}
       (id,session_id,operation_date,toll_name,booth_number,direction,operator_name,
        passed_at,main_plate,vehicle_type,main_axles,secondary_plate,secondary_axles,total_axles,sync_status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
       session_id=VALUES(session_id),operation_date=VALUES(operation_date),toll_name=VALUES(toll_name),
       booth_number=VALUES(booth_number),direction=VALUES(direction),operator_name=VALUES(operator_name),
       passed_at=VALUES(passed_at),main_plate=VALUES(main_plate),vehicle_type=VALUES(vehicle_type),
       main_axles=VALUES(main_axles),secondary_plate=VALUES(secondary_plate),
       secondary_axles=VALUES(secondary_axles),total_axles=VALUES(total_axles),sync_status=VALUES(sync_status)`,
      [r.id,r.sessionId,r.operationDate,r.tollName,r.boothNumber,r.direction,r.operatorName,
       r.passedAt,r.mainPlate,r.vehicleType,r.mainAxles,r.secondaryPlate,r.secondaryAxles,r.totalAxles,r.syncStatus]
    );
    res.json({ ok: true, recordId: r.id });
  } catch (error) { next(error); }
});

app.get('/api/records', authenticateRequest, async (req, res, next) => {
  try {
    const filters = []; const params = [];
    if (req.query.sessionId)     { filters.push('session_id = ?');     params.push(String(req.query.sessionId)); }
    if (req.query.operationDate) { filters.push('operation_date = ?'); params.push(String(req.query.operationDate)); }
    if (req.query.tollName)      { filters.push('toll_name = ?');      params.push(String(req.query.tollName)); }
    if (req.query.boothNumber)   { filters.push('booth_number = ?');   params.push(String(req.query.boothNumber)); }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const rows = await query(
      `SELECT * FROM ${TABLES.records} ${where} ORDER BY operation_date DESC, passed_at DESC, created_at DESC`,
      params
    );
    res.json({ ok: true, rows });
  } catch (error) { next(error); }
});

app.delete('/api/records/:id', authenticateRequest, async (req, res, next) => {
  try {
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
    CREATE TABLE IF NOT EXISTS ${TABLES.projects} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      name VARCHAR(120) NOT NULL,
      description TEXT NULL,
      status ENUM('activo','pausado','cerrado') NOT NULL DEFAULT 'activo',
      start_date DATE NOT NULL,
      end_date DATE NULL,
      daily_start_time TIME NULL COMMENT 'Hora inicio registro cada día',
      daily_end_time TIME NULL COMMENT 'Hora fin registro cada día',
      created_by BIGINT UNSIGNED NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS ${TABLES.stations} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      project_id INT UNSIGNED NOT NULL,
      name VARCHAR(120) NOT NULL,
      location VARCHAR(200) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      CONSTRAINT fk_cidatt_stations_project FOREIGN KEY (project_id) REFERENCES ${TABLES.projects} (id) ON DELETE CASCADE
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
    CREATE TABLE IF NOT EXISTS ${TABLES.assignments} (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      project_id INT UNSIGNED NOT NULL,
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

  // ─── SEED usuarios de prueba ──────────────────────────────────────────────
  const seedUsers = [
    { username: 'admin',            full_name: 'Administrador CIDATT',  role: 'admin',        password: 'CIDATT2026!' },
    { username: 'director.test',    full_name: 'Director de Prueba',    role: 'director',     password: 'Director2026!' },
    { username: 'coord.test',       full_name: 'Coordinador de Prueba', role: 'coordinador',  password: 'Coord2026!' },
    { username: 'registrador.test', full_name: 'Registrador de Prueba', role: 'registrador',  password: 'Reg2026!' }
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
