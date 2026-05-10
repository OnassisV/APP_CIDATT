// Generador de Excel idéntico al ejemplo (Pedro/resultados ant/*.xlsx).
// Estructura por hoja:
//   "Tabla 1": resumen de cantidad de vehículos por hora y tipo, agrupado por sentido.
//   "Tabla 2": resumen de total de ejes por hora y tipo, agrupado por sentido.
//   "Detalle": filas crudas con las 15 columnas oficiales.
//
// Encabezado institucional fila 0-5 (idéntico al ejemplo, parametrizable).

import XLSX from 'xlsx';

// Convierte una fecha YYYY-MM-DD a serial Excel (días desde 1899-12-30).
function dateToExcelSerial(yyyymmdd) {
  if (!yyyymmdd) return '';
  // Construir fecha en UTC para evitar saltos por timezone.
  const [y, m, d] = String(yyyymmdd).split('-').map(n => parseInt(n, 10));
  if (!y || !m || !d) return '';
  const utc = Date.UTC(y, m - 1, d);
  const epoch = Date.UTC(1899, 11, 30);
  return Math.round((utc - epoch) / 86400000);
}

// Genera un Buffer .xlsx para una sola unidad (peaje o conteo).
// Argumentos:
//   unitLabel:    "UNIDAD DE PEAJE CASARACRA" | "UNIDAD DE CONTEO CASAPALCA"
//   concession:   "CONCESIONARIA DEVIANDES"
//   periodLabel:  "Primer Trimestre del año 2026"
//   records:      array de registros normalizados (validator.js)
//   directions:   array de hasta 2 sentidos (orden = orden en el reporte)
export function buildUnitWorkbook({ unitLabel, concession, periodLabel, records, directions }) {
  const wb = XLSX.utils.book_new();

  // ─── Hoja Tabla 1 (vehículos) ───────────────────────────────────────────
  const tabla1 = buildPivotSheet({
    title: 'Tabla1: Resumen de total de vehiculos por hora según tipo y sentido de control',
    aggregator: 'count',
    unitLabel, concession, periodLabel, records, directions
  });
  const ws1 = XLSX.utils.aoa_to_sheet(tabla1);
  ws1['!cols'] = [{ wch: 18 }, { wch: 14 }, { wch: 14 }, { wch: 14 }, { wch: 16 }, { wch: 4 }];
  XLSX.utils.book_append_sheet(wb, ws1, 'Tabla 1');

  // ─── Hoja Tabla 2 (ejes) ────────────────────────────────────────────────
  const tabla2 = buildPivotSheet({
    title: 'Tabla 2: Resumen de total de ejes por hora según tipo y sentido de control',
    aggregator: 'axles',
    unitLabel, concession, periodLabel, records, directions
  });
  const ws2 = XLSX.utils.aoa_to_sheet(tabla2);
  ws2['!cols'] = ws1['!cols'];
  XLSX.utils.book_append_sheet(wb, ws2, 'Tabla 2');

  // ─── Hoja Detalle ──────────────────────────────────────────────────────
  const detalle = buildDetalleSheet({ unitLabel, concession, periodLabel, records });
  const ws3 = XLSX.utils.aoa_to_sheet(detalle);
  ws3['!cols'] = [
    { wch: 6 },  { wch: 8 },  { wch: 26 }, { wch: 12 }, { wch: 14 }, { wch: 14 },
    { wch: 16 }, { wch: 8 },  { wch: 18 }, { wch: 8 },  { wch: 18 }, { wch: 8 },
    { wch: 16 }, { wch: 6 },  { wch: 12 }
  ];
  XLSX.utils.book_append_sheet(wb, ws3, 'Detalle');

  return wb;
}

export function buildUnitBuffer(opts) {
  return XLSX.write(buildUnitWorkbook(opts), { type: 'buffer', bookType: 'xlsx' });
}

// ── Constructores de hojas ────────────────────────────────────────────────

function institutionalHeader(unitLabel, concession, periodLabel, ncols) {
  const pad = (n) => Array(n).fill('');
  return [
    ['Reporte de Muestra de Flujo Vehicular Relevada en campo ', ...pad(ncols - 1)],
    [`correspondiente al ${periodLabel || ''}`,                  ...pad(ncols - 1)],
    pad(ncols),
    [unitLabel || '',                                            ...pad(ncols - 1)],
    [concession || '',                                           ...pad(ncols - 1)],
    pad(ncols)
  ];
}

function buildPivotSheet({ title, aggregator, unitLabel, concession, periodLabel, records, directions }) {
  const NCOLS = 6; // 5 datos + 1 columna vacía a la derecha
  const out = institutionalHeader(unitLabel, concession, periodLabel, NCOLS);
  out.push([title, '', '', '', '', '']);
  out.push(['', '', '', '', '', '']);

  const dirList = directions && directions.length ? directions : ['Sentido único'];
  const HOURS = Array.from({ length: 12 }, (_, i) => i + 8); // 8..19 como en la muestra

  for (let d = 0; d < dirList.length; d++) {
    const dir = dirList[d];
    out.push(['Sentido', dir, '', '', '', '']);
    out.push(['', '', '', '', '', '']);
    out.push([' ', ' ', '', '', '', '']);
    out.push(['Fecha y Hora', 'Ligeros', 'Pesados', 'M2', 'Total general', '']);

    const dirRecords = records.filter(r => (r.sentido || '') === dir);
    // Agrupar por fecha
    const byDate = new Map();
    for (const r of dirRecords) {
      if (!r.fecha) continue;
      if (!byDate.has(r.fecha)) byDate.set(r.fecha, []);
      byDate.get(r.fecha).push(r);
    }
    const fechas = Array.from(byDate.keys()).sort();
    let grandL = 0, grandP = 0, grandM = 0;

    for (const fecha of fechas) {
      const dayRecs = byDate.get(fecha);
      const dayL = sumBy(dayRecs, 'Ligeros', aggregator);
      const dayP = sumBy(dayRecs, 'Pesados', aggregator);
      const dayM = sumBy(dayRecs, 'M2', aggregator);
      grandL += dayL; grandP += dayP; grandM += dayM;
      // Fila resumen del día (fecha serial)
      out.push([dateToExcelSerial(fecha), dayL, dayP, dayM, dayL + dayP + dayM, '']);
      // Filas por hora
      for (const h of HOURS) {
        const hourRecs = dayRecs.filter(r => Number(r.hora_bloque) === h);
        const hL = sumBy(hourRecs, 'Ligeros', aggregator);
        const hP = sumBy(hourRecs, 'Pesados', aggregator);
        const hM = sumBy(hourRecs, 'M2', aggregator);
        out.push([h, hL, hP, hM, hL + hP + hM, '']);
      }
    }

    if (!fechas.length) {
      // Sin datos: escribir filas vacías de horas
      out.push(['', 0, 0, 0, 0, '']);
      for (const h of HOURS) out.push([h, 0, 0, 0, 0, '']);
    }

    // Total general del sentido
    out.push(['Total general', grandL, grandP, grandM, grandL + grandP + grandM, '']);

    // Bloque de filas vacías como en la muestra (separador antes del siguiente sentido)
    if (d < dirList.length - 1) {
      for (let k = 0; k < 17; k++) out.push(['', '', '', '', '', '']);
    }
  }

  return out;
}

function sumBy(records, group, aggregator) {
  let acc = 0;
  for (const r of records) {
    if ((r.tipo_grupo || '') !== group) continue;
    if (aggregator === 'count') acc += 1;
    else if (aggregator === 'axles') acc += Number(r.total_ejes) || 0;
  }
  return acc;
}

function buildDetalleSheet({ unitLabel, concession, periodLabel, records }) {
  const NCOLS = 15;
  const out = institutionalHeader(unitLabel, concession, periodLabel, NCOLS);
  out.push([
    'Id', 'Caseta', 'Sentido', 'Fecha', 'Hora de Paso',
    'Placa Principal', 'Tipo de Vehiculo', 'N°  Ejes',
    'Placa Semi Remolque', 'N°  Ejes',
    'Placa Semi -Remolque', 'N°  Ejes',
    'N° Total de Ejes', 'Hora', 'Tipo'
  ]);
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    out.push([
      i + 1,
      r.caseta != null && r.caseta !== '' ? r.caseta : '',
      r.sentido || '',
      r.fecha ? dateToExcelSerial(r.fecha) : '',
      r.hora_paso ? timeToExcelFraction(r.hora_paso) : '',
      r.placa_principal || '',
      r.tipo_vehiculo || '',
      r.ejes_principal != null ? r.ejes_principal : '',
      r.placa_semi1 || '',
      r.placa_semi1 ? (r.ejes_semi1 || '') : '',
      r.placa_semi2 || '',
      r.placa_semi2 ? (r.ejes_semi2 || '') : '',
      r.total_ejes != null ? r.total_ejes : '',
      r.hora_bloque != null ? r.hora_bloque : '',
      r.tipo_grupo || ''
    ]);
  }
  return out;
}

function timeToExcelFraction(hhmmss) {
  const m = String(hhmmss).match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (!m) return '';
  const h = parseInt(m[1], 10);
  const mm = parseInt(m[2], 10);
  const s = parseInt(m[3] || '0', 10);
  return (h * 3600 + mm * 60 + s) / 86400;
}
