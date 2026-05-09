// Plantilla Excel para procesamiento externo.
// Replica las columnas exactas de la hoja "Detalle" de los archivos de muestra
// (Pedro/resultados ant/*.xlsx) para que el director pueda preparar archivos
// que el motor reconozca sin ambiguedades.

import XLSX from 'xlsx';

// Encabezados oficiales (orden y texto idénticos al ejemplo).
// IMPORTANTE: los textos llevan dobles espacios y guiones donde corresponde.
export const TEMPLATE_HEADERS = [
  'Id',
  'Caseta',
  'Sentido',
  'Fecha',
  'Hora de Paso',
  'Placa Principal',
  'Tipo de Vehiculo',
  'N°  Ejes',
  'Placa Semi Remolque',
  'N°  Ejes',          // ejes del semi remolque
  'Placa Semi -Remolque',
  'N°  Ejes',          // ejes del segundo semi
  'N° Total de Ejes',
  'Hora',              // hora entera (0-23) para agrupacion
  'Tipo'               // 'Ligeros' | 'Pesados' | 'M2'
];

// Filas de ejemplo para que el director vea qué se espera.
const SAMPLE_ROWS = [
  [1, 1, 'La Oroya - Cerro de Pasco', '2026-04-01', '08:00:00', 'CEV850',  'L', 2, '',       '', '', '', 2, 8, 'Ligeros'],
  [2, 1, 'La Oroya - Cerro de Pasco', '2026-04-01', '08:05:00', 'C4V768',  'C', 3, 'F2U985', 3, '', '', 6, 8, 'Pesados'],
  [3, 2, 'Cerro de Pasco - La Oroya', '2026-04-01', '08:07:00', 'BAI844',  'M2', 2, '',      '', '', '', 2, 8, 'M2'],
];

const INSTRUCTIONS_LINES = [
  ['CIDATT — Plantilla de Procesamiento de Relevamiento Vehicular'],
  [''],
  ['Esta plantilla define las columnas requeridas para procesar datos externos.'],
  ['Use la pestaña "Detalle" para cargar sus registros (puede ser una fila por vehículo).'],
  [''],
  ['REGLAS:'],
  ['• Las columnas deben tener exactamente estos nombres y en este orden.'],
  ['• "Sentido" debe ser uno de los dos sentidos del peaje (texto consistente).'],
  ['• "Fecha" formato YYYY-MM-DD (ej. 2026-04-01).'],
  ['• "Hora de Paso" formato HH:MM:SS (ej. 08:00:00).'],
  ['• "Placa Principal" mayúsculas, sin guiones ni espacios.'],
  ['• "Tipo de Vehiculo" debe ser: L, C, M2, O, PNP o A.'],
  ['• "N°  Ejes" entero >= 1.'],
  ['• "Placa Semi Remolque" / "Placa Semi -Remolque" pueden quedar vacías si no aplica.'],
  ['• "N° Total de Ejes" debe ser la suma de los ejes (principal + semi).'],
  ['• "Hora" entero 0-23 (hora de inicio del bloque, para Tabla 1 y Tabla 2).'],
  ['• "Tipo" en español: "Ligeros", "Pesados" o "M2".'],
  [''],
  ['Las filas de la pestaña "Detalle" se incluyen como ejemplo. Bórrelas antes de cargar sus datos.'],
];

export function buildTemplateWorkbook() {
  const wb = XLSX.utils.book_new();

  // Hoja Instrucciones
  const wsInfo = XLSX.utils.aoa_to_sheet(INSTRUCTIONS_LINES);
  wsInfo['!cols'] = [{ wch: 110 }];
  XLSX.utils.book_append_sheet(wb, wsInfo, 'Instrucciones');

  // Hoja Detalle: encabezados + filas de ejemplo
  const detalleAOA = [TEMPLATE_HEADERS, ...SAMPLE_ROWS];
  const wsDetalle = XLSX.utils.aoa_to_sheet(detalleAOA);
  wsDetalle['!cols'] = TEMPLATE_HEADERS.map((h) => ({ wch: Math.max(12, h.length + 2) }));
  XLSX.utils.book_append_sheet(wb, wsDetalle, 'Detalle');

  return wb;
}

export function buildTemplateBuffer() {
  const wb = buildTemplateWorkbook();
  return XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
}
