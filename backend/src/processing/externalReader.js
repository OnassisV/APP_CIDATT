// Lectura/parseo de archivos externos (Excel) cargados por el director.
// Acepta el formato de la plantilla oficial (hoja "Detalle") y devuelve
// un array uniforme de registros para alimentar al validador.

import XLSX from 'xlsx';
import { TEMPLATE_HEADERS } from './template.js';

const HEADER_ALIASES = {
  'id': ['id', 'n', 'n°', '#'],
  'caseta': ['caseta', 'caseta n°', 'cabina'],
  'sentido': ['sentido', 'direccion', 'dirección'],
  'fecha': ['fecha'],
  'hora_paso': ['hora de paso', 'hora paso', 'hora'],
  'placa_principal': ['placa principal', 'placa'],
  'tipo_vehiculo': ['tipo de vehiculo', 'tipo de vehículo', 'tipo vehiculo'],
  'ejes_principal': ['n° ejes', 'n ejes', 'ejes', 'n°  ejes'],
  'placa_semi1': ['placa semi remolque'],
  'ejes_semi1': null,        // segunda columna "N°  Ejes"
  'placa_semi2': ['placa semi -remolque', 'placa semi - remolque', 'placa semi-remolque'],
  'ejes_semi2': null,        // tercera columna "N°  Ejes"
  'total_ejes': ['n° total de ejes', 'n total de ejes', 'total ejes', 'total de ejes'],
  'hora_bloque': ['hora bloque', 'hora_bloque'],
  'tipo_grupo': ['tipo (ligeros/pesados/m2)', 'tipo grupo']
};

function normHeader(s) {
  return String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

// Construye un mapa de índice de columna → campo destino, basado en el
// orden EXACTO de la plantilla (que tiene 3 columnas con el mismo nombre
// "N°  Ejes"). Las que no coinciden con la plantilla se intentan resolver
// por alias.
function buildColumnMap(headerRow) {
  // Si los 15 encabezados coinciden con la plantilla por orden, usamos índices fijos.
  const looksLikeTemplate = headerRow.length >= 13 && TEMPLATE_HEADERS.every((h, i) => normHeader(headerRow[i]) === normHeader(h));
  if (looksLikeTemplate) {
    return {
      id: 0,
      caseta: 1,
      sentido: 2,
      fecha: 3,
      hora_paso: 4,
      placa_principal: 5,
      tipo_vehiculo: 6,
      ejes_principal: 7,
      placa_semi1: 8,
      ejes_semi1: 9,
      placa_semi2: 10,
      ejes_semi2: 11,
      total_ejes: 12,
      hora_bloque: headerRow.length > 13 ? 13 : null,
      tipo_grupo: headerRow.length > 14 ? 14 : null
    };
  }

  // Fallback: por alias (no soporta nombres duplicados).
  const map = {};
  const used = new Set();
  for (const [field, aliases] of Object.entries(HEADER_ALIASES)) {
    if (!aliases) continue;
    for (let i = 0; i < headerRow.length; i++) {
      if (used.has(i)) continue;
      const cell = normHeader(headerRow[i]);
      if (aliases.includes(cell)) {
        map[field] = i;
        used.add(i);
        break;
      }
    }
  }
  return map;
}

export function parseExternalWorkbook(buffer) {
  const wb = XLSX.read(buffer, { type: 'buffer', cellDates: true });
  // Buscar hoja "Detalle" (case-insensitive) o usar primera hoja útil.
  let sheetName = wb.SheetNames.find(n => normHeader(n) === 'detalle');
  if (!sheetName) {
    // Saltar hoja Instrucciones si está al inicio
    sheetName = wb.SheetNames.find(n => normHeader(n) !== 'instrucciones') || wb.SheetNames[0];
  }
  if (!sheetName) {
    throw Object.assign(new Error('El archivo no contiene hojas legibles.'), { status: 400 });
  }

  const ws = wb.Sheets[sheetName];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: '' });
  if (!rows.length) {
    throw Object.assign(new Error('La hoja está vacía.'), { status: 400 });
  }

  // El encabezado puede no estar en la fila 0 si el director conserva el
  // texto institucional. Buscar la primera fila que contenga "Placa Principal".
  let headerIdx = rows.findIndex(r => r.some(c => normHeader(c) === 'placa principal'));
  if (headerIdx < 0) headerIdx = 0;

  const headerRow = rows[headerIdx];
  const map = buildColumnMap(headerRow);

  // Validar columnas mínimas indispensables
  const required = ['placa_principal', 'tipo_vehiculo', 'fecha', 'hora_paso'];
  const missing = required.filter(k => map[k] == null);
  if (missing.length) {
    const labels = {
      placa_principal: 'Placa Principal',
      tipo_vehiculo: 'Tipo de Vehiculo',
      fecha: 'Fecha',
      hora_paso: 'Hora de Paso'
    };
    throw Object.assign(
      new Error(`Faltan columnas obligatorias: ${missing.map(k => labels[k]).join(', ')}.`),
      { status: 400, missing }
    );
  }

  // Extraer registros
  const out = [];
  for (let i = headerIdx + 1; i < rows.length; i++) {
    const row = rows[i];
    if (!row || row.every(c => c === '' || c == null)) continue;
    const get = (k) => map[k] != null ? row[map[k]] : '';
    out.push({
      id: get('id'),
      caseta: get('caseta'),
      sentido: get('sentido'),
      fecha: get('fecha'),
      hora_paso: get('hora_paso'),
      placa_principal: get('placa_principal'),
      tipo_vehiculo: get('tipo_vehiculo'),
      ejes_principal: get('ejes_principal'),
      placa_semi1: get('placa_semi1'),
      ejes_semi1: get('ejes_semi1'),
      placa_semi2: get('placa_semi2'),
      ejes_semi2: get('ejes_semi2'),
      total_ejes: get('total_ejes'),
      hora_bloque: get('hora_bloque'),
      tipo_grupo: get('tipo_grupo')
    });
  }

  return { sheetName, headerRow, columnMap: map, records: out };
}
