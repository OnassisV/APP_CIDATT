// Generador de Excel idéntico al ejemplo (Pedro/resultados ant/*.xlsx).
// Usa ExcelJS para poder escribir formatos completos: anchos, alturas, merges,
// formato de fecha "m/d/yy", fuentes y encabezado institucional.
//
// Hojas:
//   "Tabla 1": resumen de cantidad de vehículos por hora y tipo, agrupado por sentido.
//   "Tabla 2": resumen de total de ejes por hora y tipo, agrupado por sentido.
//   "Detalle": filas crudas con las 15 columnas oficiales.

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const ExcelJS = require('exceljs');

const HOURS = Array.from({ length: 12 }, (_, i) => i + 8); // 8..19

// ── Helpers ───────────────────────────────────────────────────────────────

// Serial Excel para una fecha YYYY-MM-DD.
function dateToExcelSerial(yyyymmdd) {
  if (!yyyymmdd) return null;
  const [y, m, d] = String(yyyymmdd).split('-').map(n => parseInt(n, 10));
  if (!y || !m || !d) return null;
  const utc = Date.UTC(y, m - 1, d);
  const epoch = Date.UTC(1899, 11, 30);
  return Math.round((utc - epoch) / 86400000);
}

function timeToExcelFraction(hhmmss) {
  const m = String(hhmmss).match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (!m) return null;
  const h = parseInt(m[1], 10);
  const mm = parseInt(m[2], 10);
  const s = parseInt(m[3] || '0', 10);
  return (h * 3600 + mm * 60 + s) / 86400;
}

const QUARTER_NAMES = ['Primer', 'Segundo', 'Tercer', 'Cuarto'];

// Determina el período automáticamente: "Primer/Segundo/... Trimestre del año YYYY"
// a partir de las fechas reales (records[].fecha) o, en su defecto, del label dado.
export function inferPeriodLabel(records, fallback) {
  const dates = (records || [])
    .map(r => r && r.fecha)
    .filter(Boolean)
    .sort();
  if (!dates.length) return fallback || '';
  const first = dates[0];
  const last = dates[dates.length - 1];
  const [y1, m1] = first.split('-').map(n => parseInt(n, 10));
  const [y2, m2] = last.split('-').map(n => parseInt(n, 10));
  const q1 = Math.ceil(m1 / 3);
  const q2 = Math.ceil(m2 / 3);
  if (y1 === y2 && q1 === q2) {
    return `${QUARTER_NAMES[q1 - 1]} Trimestre del año ${y1}`;
  }
  // Si abarca varios trimestres/años, devolver rango legible.
  return `período del ${first} al ${last}`;
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

// ── Construcción del libro ────────────────────────────────────────────────

export async function buildUnitWorkbook({ unitLabel, concession, periodLabel, records, directions }) {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'CIDATT';
  wb.created = new Date();

  const period = periodLabel || inferPeriodLabel(records, '');

  buildPivotSheet(wb.addWorksheet('Tabla 1', { properties: { defaultRowHeight: 16.5 } }), {
    title: 'Tabla1: Resumen de total de vehiculos por hora según tipo y sentido de control',
    aggregator: 'count',
    unitLabel, concession, periodLabel: period, records, directions
  });
  buildPivotSheet(wb.addWorksheet('Tabla 2', { properties: { defaultRowHeight: 16.5 } }), {
    title: 'Tabla 2: Resumen de total de ejes por hora según tipo y sentido de control',
    aggregator: 'axles',
    unitLabel, concession, periodLabel: period, records, directions
  });
  buildDetalleSheet(wb.addWorksheet('Detalle', { properties: { defaultRowHeight: 15 } }), {
    unitLabel, concession, periodLabel: period, records
  });
  return wb;
}

export async function buildUnitBuffer(opts) {
  const wb = await buildUnitWorkbook(opts);
  return await wb.xlsx.writeBuffer();
}

// ── Hoja institucional + pivot ─────────────────────────────────────────────

function applyInstitutionalHeader(sheet, unitLabel, concession, periodLabel, ncols) {
  // 5 columnas de datos (A..E) y mergeamos A:E para los 4 títulos.
  // Anchos de columna replicando muestra
  sheet.columns = [
    { width: 19.71 },
    { width: 25.71 },
    { width: 25.71 },
    { width: 25.71 },
    { width: 18.14 },
    { width: 4 }
  ];

  const titleStyle = { font: { name: 'Calibri', size: 11, bold: true }, alignment: { horizontal: 'center', vertical: 'middle' } };
  const subtitleStyle = { font: { name: 'Calibri', size: 11, italic: true }, alignment: { horizontal: 'center', vertical: 'middle' } };

  sheet.getCell('A1').value = 'Reporte de Muestra de Flujo Vehicular Relevada en campo ';
  sheet.mergeCells('A1:E1');
  Object.assign(sheet.getCell('A1'), titleStyle);
  sheet.getRow(1).height = 24.75;

  sheet.getCell('A2').value = `correspondiente al ${periodLabel || ''}`;
  sheet.mergeCells('A2:E2');
  Object.assign(sheet.getCell('A2'), subtitleStyle);
  sheet.getRow(2).height = 24.75;

  sheet.getRow(3).height = 24.75;

  sheet.getCell('A4').value = unitLabel || '';
  sheet.mergeCells('A4:E4');
  Object.assign(sheet.getCell('A4'), titleStyle);
  sheet.getRow(4).height = 24.75;

  sheet.getCell('A5').value = concession || '';
  sheet.mergeCells('A5:E5');
  Object.assign(sheet.getCell('A5'), { font: { name: 'Calibri', size: 11 }, alignment: { horizontal: 'center', vertical: 'middle' } });
  sheet.getRow(5).height = 29.25;

  sheet.getRow(6).height = 15.75;
}

function buildPivotSheet(sheet, { title, aggregator, unitLabel, concession, periodLabel, records, directions }) {
  applyInstitutionalHeader(sheet, unitLabel, concession, periodLabel, 5);

  // Título de la tabla
  sheet.getCell('A7').value = title;
  Object.assign(sheet.getCell('A7'), {
    font: { name: 'Calibri', size: 11, bold: true },
    alignment: { horizontal: 'left', vertical: 'middle' }
  });
  sheet.getRow(7).height = 27.75;
  sheet.getRow(8).height = 27.75;

  const dirList = (directions && directions.length) ? directions : ['Sentido único'];

  let row = 9; // primera fila para "Sentido | <nombre>"
  for (let d = 0; d < dirList.length; d++) {
    const dir = dirList[d];
    sheet.getCell(`A${row}`).value = 'Sentido';
    sheet.getCell(`B${row}`).value = dir;
    Object.assign(sheet.getCell(`A${row}`), { font: { name: 'Calibri', size: 11, bold: true } });
    Object.assign(sheet.getCell(`B${row}`), { font: { name: 'Calibri', size: 11, bold: true } });
    sheet.getRow(row).height = 19.5;
    row++;

    sheet.getRow(row).height = 23.25; // separador vacío
    row++;

    sheet.getCell(`A${row}`).value = ' ';
    sheet.getCell(`B${row}`).value = ' ';
    sheet.getRow(row).height = 16.5;
    row++;

    // Encabezado de columnas
    const headers = ['Fecha y Hora', 'Ligeros', 'Pesados', 'M2', 'Total general'];
    const headerStyle = {
      font: { name: 'Calibri', size: 11, bold: true, color: { argb: 'FFFFFFFF' } },
      alignment: { horizontal: 'center', vertical: 'middle' },
      fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F4E78' } },
      border: {
        top: { style: 'thin', color: { argb: 'FF000000' } },
        bottom: { style: 'thin', color: { argb: 'FF000000' } },
        left: { style: 'thin', color: { argb: 'FF000000' } },
        right: { style: 'thin', color: { argb: 'FF000000' } }
      }
    };
    headers.forEach((h, i) => {
      const cell = sheet.getCell(row, i + 1);
      cell.value = h;
      Object.assign(cell, headerStyle);
    });
    sheet.getRow(row).height = 16.5;
    row++;

    // Datos por fecha y hora
    const dirRecords = records.filter(r => (r.sentido || '') === dir);
    const byDate = new Map();
    for (const r of dirRecords) {
      if (!r.fecha) continue;
      if (!byDate.has(r.fecha)) byDate.set(r.fecha, []);
      byDate.get(r.fecha).push(r);
    }
    const fechas = Array.from(byDate.keys()).sort();
    let grandL = 0, grandP = 0, grandM = 0;

    const dataAlign = { horizontal: 'right', vertical: 'middle' };
    const dataBorder = {
      top: { style: 'thin', color: { argb: 'FFBFBFBF' } },
      bottom: { style: 'thin', color: { argb: 'FFBFBFBF' } },
      left: { style: 'thin', color: { argb: 'FFBFBFBF' } },
      right: { style: 'thin', color: { argb: 'FFBFBFBF' } }
    };

    const writeDataRow = (values, opts = {}) => {
      values.forEach((v, i) => {
        const cell = sheet.getCell(row, i + 1);
        cell.value = v;
        cell.alignment = i === 0 ? { horizontal: 'left', vertical: 'middle' } : dataAlign;
        cell.font = { name: 'Calibri', size: 11, bold: !!opts.bold };
        cell.border = dataBorder;
        if (opts.fill) cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: opts.fill } };
        if (i === 0 && opts.dateFormat) cell.numFmt = 'm/d/yy';
      });
      sheet.getRow(row).height = opts.height || 23.25;
      row++;
    };

    for (const fecha of fechas) {
      const dayRecs = byDate.get(fecha);
      const dayL = sumBy(dayRecs, 'Ligeros', aggregator);
      const dayP = sumBy(dayRecs, 'Pesados', aggregator);
      const dayM = sumBy(dayRecs, 'M2', aggregator);
      grandL += dayL; grandP += dayP; grandM += dayM;
      // Resumen del día (fecha como serial con formato m/d/yy)
      writeDataRow([
        dateToExcelSerial(fecha), dayL, dayP, dayM, dayL + dayP + dayM
      ], { bold: true, fill: 'FFD9E1F2', dateFormat: true });
      // Filas por hora
      for (const h of HOURS) {
        const hr = dayRecs.filter(r => Number(r.hora_bloque) === h);
        const hL = sumBy(hr, 'Ligeros', aggregator);
        const hP = sumBy(hr, 'Pesados', aggregator);
        const hM = sumBy(hr, 'M2', aggregator);
        writeDataRow([h, hL, hP, hM, hL + hP + hM], { height: 16.5 });
      }
    }

    if (!fechas.length) {
      writeDataRow(['', 0, 0, 0, 0], { bold: true, fill: 'FFD9E1F2' });
      for (const h of HOURS) writeDataRow([h, 0, 0, 0, 0], { height: 16.5 });
    }

    // Total general del sentido
    writeDataRow([
      'Total general', grandL, grandP, grandM, grandL + grandP + grandM
    ], { bold: true, fill: 'FFFFF2CC' });

    // Separador antes del siguiente sentido (17 filas vacías)
    if (d < dirList.length - 1) {
      for (let k = 0; k < 17; k++) {
        sheet.getRow(row).height = 23.25;
        row++;
      }
    }
  }
}

// ── Hoja Detalle (15 columnas) ─────────────────────────────────────────────

function buildDetalleSheet(sheet, { unitLabel, concession, periodLabel, records }) {
  sheet.columns = [
    { width: 10.14 }, { width: 10 },    { width: 30.85 }, { width: 18 },
    { width: 15.71 }, { width: 18 },    { width: 22 },    { width: 10 },
    { width: 22 },    { width: 10 },    { width: 22 },    { width: 10 },
    { width: 16 },    { width: 8 },     { width: 12 }
  ];

  const titleStyle = { font: { name: 'Calibri', size: 11, bold: true }, alignment: { horizontal: 'center', vertical: 'middle' } };

  sheet.getCell('A1').value = 'Reporte de Muestra de Flujo Vehicular Relevada en campo ';
  sheet.mergeCells('A1:M1');
  Object.assign(sheet.getCell('A1'), titleStyle);

  sheet.getCell('A2').value = `correspondiente al ${periodLabel || ''}`;
  sheet.mergeCells('A2:M2');
  Object.assign(sheet.getCell('A2'), { font: { name: 'Calibri', size: 11, italic: true }, alignment: { horizontal: 'center' } });

  sheet.getCell('A4').value = unitLabel || '';
  sheet.mergeCells('A4:M4');
  Object.assign(sheet.getCell('A4'), titleStyle);

  sheet.getCell('A5').value = concession || '';
  sheet.mergeCells('A5:M5');
  Object.assign(sheet.getCell('A5'), { font: { name: 'Calibri', size: 11 }, alignment: { horizontal: 'center' } });

  // Encabezado de tabla en fila 7
  const headers = [
    'Id', 'Caseta', 'Sentido', 'Fecha', 'Hora de Paso',
    'Placa Principal', 'Tipo de Vehiculo', 'N°  Ejes',
    'Placa Semi Remolque', 'N°  Ejes',
    'Placa Semi -Remolque', 'N°  Ejes',
    'N° Total de Ejes', 'Hora', 'Tipo'
  ];
  const headerStyle = {
    font: { name: 'Calibri', size: 11, bold: true, color: { argb: 'FFFFFFFF' } },
    alignment: { horizontal: 'center', vertical: 'middle', wrapText: true },
    fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F4E78' } },
    border: {
      top: { style: 'thin' }, bottom: { style: 'thin' },
      left: { style: 'thin' }, right: { style: 'thin' }
    }
  };
  headers.forEach((h, i) => {
    const cell = sheet.getCell(7, i + 1);
    cell.value = h;
    Object.assign(cell, headerStyle);
  });
  sheet.getRow(7).height = 30;

  // Datos a partir de la fila 8
  const cellBorder = {
    top: { style: 'thin', color: { argb: 'FFBFBFBF' } },
    bottom: { style: 'thin', color: { argb: 'FFBFBFBF' } },
    left: { style: 'thin', color: { argb: 'FFBFBFBF' } },
    right: { style: 'thin', color: { argb: 'FFBFBFBF' } }
  };

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const rowIdx = 8 + i;
    const values = [
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
    ];
    values.forEach((v, c) => {
      const cell = sheet.getCell(rowIdx, c + 1);
      cell.value = v;
      cell.font = { name: 'Calibri', size: 10 };
      cell.border = cellBorder;
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
      if (c === 3) cell.numFmt = 'm/d/yy';   // Fecha
      if (c === 4) cell.numFmt = 'h:mm:ss AM/PM'; // Hora de Paso
    });
  }
}
