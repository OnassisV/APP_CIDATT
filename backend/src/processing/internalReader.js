// Carga registros internos (un proyecto del propio sistema) y los normaliza al
// formato que entiende el validador y el generador de Excel.

import { vehicleGroup } from './validator.js';

// `query` se inyecta para evitar import circular con server.js.
export async function loadInternalProject(query, TABLES, projectId) {
  const projects = await query(
    `SELECT p.id, p.name, p.start_date, p.end_date, p.status,
            c.id AS concession_id, c.name AS concession_name
       FROM ${TABLES.projects} p
       LEFT JOIN ${TABLES.concessions} c ON c.id = p.concession_id
      WHERE p.id = ? LIMIT 1`,
    [projectId]
  );
  if (!projects.length) {
    throw Object.assign(new Error('Proyecto no encontrado.'), { status: 404 });
  }
  const project = projects[0];

  const stations = await query(
    `SELECT DISTINCT ts.id, ts.name, ts.location, ts.daily_start_time, ts.daily_end_time
       FROM ${TABLES.stations} ts
       INNER JOIN ${TABLES.projectSites} ps ON ps.station_id = ts.id AND ps.project_id = ?
      ORDER BY ts.name`,
    [projectId]
  );

  const records = await query(
    `SELECT r.id, r.operation_date, r.passed_at, r.toll_name, r.booth_number, r.direction,
            r.main_plate, r.vehicle_type, r.main_axles,
            r.secondary_plate, r.secondary_axles, r.total_axles, r.is_fugitive,
            r.station_id, r.booth_id
       FROM ${TABLES.records} r
      WHERE r.project_id = ?
      ORDER BY r.operation_date, r.passed_at, r.id`,
    [projectId]
  );

  const normalized = records.map((r, idx) => {
    const tipo = String(r.vehicle_type || '').toUpperCase();
    const fecha = r.operation_date instanceof Date
      ? r.operation_date.toISOString().slice(0, 10)
      : String(r.operation_date || '').slice(0, 10);
    const hora = r.passed_at ? String(r.passed_at).slice(0, 8) : null;
    return {
      id: idx + 1,
      _record_uuid: r.id,
      caseta: r.booth_number || '',
      sentido: r.direction || '',
      fecha,
      hora_paso: hora,
      placa_principal: r.main_plate || '',
      tipo_vehiculo: tipo,
      ejes_principal: r.main_axles || 0,
      placa_semi1: r.secondary_plate || '',
      ejes_semi1: r.secondary_axles || 0,
      placa_semi2: '',
      ejes_semi2: 0,
      total_ejes: r.total_axles || 0,
      hora_bloque: hora ? parseInt(hora.substring(0, 2), 10) : null,
      tipo_grupo: vehicleGroup(tipo),
      _toll_name: r.toll_name,
      _is_fugitive: !!r.is_fugitive,
      _station_id: r.station_id
    };
  });

  return { project, stations, records: normalized };
}
