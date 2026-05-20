// Generador de informe Word (.docx) editable, replicando la estructura del
// "Informe_Ositran_DEVIANDES.pdf" de muestra. Estructura:
//
//   Página 1: portada institucional con título completo del informe.
//   Página 2: "MUESTRA DE FLUJO VEHICULAR RELEVADA DE CAMPO" + introducción.
//   Página 3: "Tabla 1: Tamaño de la muestra" (fila con la unidad actual).
//   Por sentido: hoja con encabezado institucional + Tabla 1 (vehículos por hora).
//   Por sentido: hoja con encabezado institucional + Tabla 2 (ejes por hora).
//
// Todos los textos son plantilla y editables: el director ajusta detalles
// específicos del concesionario / período / firmas en el documento generado.

import {
  Document, Packer, Paragraph, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, HeightRule, BorderStyle, TextRun, PageBreak,
  ShadingType, VerticalAlign, ImageRun, Header, Footer
} from 'docx';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Colores institucionales
const NAVY = '1B3A66';        // azul oscuro de la portada del PDF
const LIGHT_BLUE = 'A9C9E2';  // celeste de la caja del logo CIDATT
const NO_BORDER = { top: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }, bottom: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }, left: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }, right: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }, insideHorizontal: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }, insideVertical: { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' } };

// Carpeta opcional con logos institucionales personalizables.
// Si existen, se incrustarán; en caso contrario, se inserta un placeholder
// blanco que puede sustituirse desde Word con clic derecho → "Cambiar imagen".
const LOGO_DIR = path.resolve(__dirname, '..', '..', 'assets', 'logos');
function loadLogoBuffer(filename) {
  try {
    const p = path.join(LOGO_DIR, filename);
    if (fs.existsSync(p)) return fs.readFileSync(p);
  } catch (_) {}
  return null;
}
// Contador global de IDs únicos para wp:docPr.
// docx@9.6.1 tiene un bug: cada DocProperties crea su propio contador local desde 0,
// por lo que TODOS los <wp:docPr> generados terminan con id="1" y Word/Mac
// rechaza el archivo ("Word detectó un error al intentar abrir el archivo").
// Solución: pasar altText.id explícito y único en cada ImageRun.
let __docPrIdCounter = 1000;
function nextDocPrId() { return ++__docPrIdCounter; }

// Helper centralizado para crear ImageRun con id + name SIEMPRE únicos y
// con un buffer clonado por instancia (algunas versiones de Word marcan el
// archivo como dañado si dos imágenes comparten exactamente el mismo nombre
// o referencia de buffer). Devuelve un ImageRun listo para insertar.
function imageRun(buf, { width, height, type, label }) {
  const id = nextDocPrId();
  const safeLabel = (label || 'imagen').replace(/[^a-zA-Z0-9._-]/g, '_');
  // type es OBLIGATORIO en docx@9.x: si se omite, los archivos en word/media/
  // se guardan como .undefined y Word marca el .docx como dañado.
  const safeType = type || 'png';
  return new ImageRun({
    data: Buffer.from(buf),
    transformation: { width, height },
    type: safeType,
    altText: {
      id,
      title: `${safeLabel}_${id}`,
      description: `${safeLabel} (id ${id})`,
      name:  `${safeLabel}_${id}`
    }
  });
}

// Devuelve un ImageRun si existe el archivo del logo, o un TextRun de marcador
// editable si no existe (evita el PNG corrupto que mostraba 'No se puede mostrar la imagen').
function logoRun(filename, widthPx, heightPx, label) {
  const buf = loadLogoBuffer(filename);
  if (buf) {
    return imageRun(buf, { width: widthPx, height: heightPx, label: filename.replace(/\.[a-z0-9]+$/i, '') });
  }
  // Sin archivo: texto editable centrado, el usuario pega su imagen encima.
  return new TextRun({ text: label || '[ Insertar logo aquí ]', bold: true, color: '1B3A66', size: 22, font: 'Arial' });
}

const HOURS = Array.from({ length: 12 }, (_, i) => i + 8);

// ── Helpers de párrafo / celda ────────────────────────────────────────────

function P(text, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { after: opts.afterSpacing != null ? opts.afterSpacing : 160, before: opts.beforeSpacing || 0 },
    children: (Array.isArray(text) ? text : [text]).map(t =>
      typeof t === 'string'
        ? new TextRun({ text: t, bold: !!opts.bold, italics: !!opts.italic, size: opts.size || 22, color: opts.color, font: 'Arial' })
        : t
    )
  });
}

function H(text, level, opts = {}) {
  const map = { 1: HeadingLevel.HEADING_1, 2: HeadingLevel.HEADING_2, 3: HeadingLevel.HEADING_3 };
  return new Paragraph({
    heading: map[level] || HeadingLevel.HEADING_2,
    alignment: opts.align || AlignmentType.LEFT,
    spacing: { before: opts.beforeSpacing != null ? opts.beforeSpacing : 240, after: opts.afterSpacing != null ? opts.afterSpacing : 120 },
    children: [new TextRun({ text: String(text), bold: true, color: opts.color || '1F4E78', size: opts.size, font: 'Arial' })]
  });
}

function tableCell(text, opts = {}) {
  return new TableCell({
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    shading: opts.shade ? { type: ShadingType.CLEAR, color: 'auto', fill: opts.shade } : undefined,
    verticalAlign: 'center',
    children: [new Paragraph({
      alignment: opts.align || AlignmentType.CENTER,
      spacing: { before: 0, after: 0 },
      children: [new TextRun({
        text: String(text == null ? '' : text),
        bold: !!opts.bold,
        color: opts.color,
        size: opts.size || 20,
        font: 'Arial'
      })]
    })]
  });
}

function pivotTable({ records, aggregator }) {
  const rows = [
    new TableRow({
      tableHeader: true,
      children: [
        tableCell('Fecha y Hora', { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Ligeros',      { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Pesados',      { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('M2',           { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Total general',{ bold: true, shade: '1F4E78', color: 'FFFFFF' })
      ]
    })
  ];

  const byDate = new Map();
  for (const r of records) {
    if (!r.fecha) continue;
    if (!byDate.has(r.fecha)) byDate.set(r.fecha, []);
    byDate.get(r.fecha).push(r);
  }
  const fechas = Array.from(byDate.keys()).sort();
  let gL = 0, gP = 0, gM = 0;

  for (const fecha of fechas) {
    const dayRecs = byDate.get(fecha);
    const dL = sumBy(dayRecs, 'Ligeros', aggregator);
    const dP = sumBy(dayRecs, 'Pesados', aggregator);
    const dM = sumBy(dayRecs, 'M2', aggregator);
    gL += dL; gP += dP; gM += dM;
    const fechaTxt = formatDate(fecha);
    rows.push(new TableRow({
      children: [
        tableCell(fechaTxt, { bold: true, shade: 'D9E1F2' }),
        tableCell(dL,       { bold: true, shade: 'D9E1F2' }),
        tableCell(dP,       { bold: true, shade: 'D9E1F2' }),
        tableCell(dM,       { bold: true, shade: 'D9E1F2' }),
        tableCell(dL+dP+dM, { bold: true, shade: 'D9E1F2' })
      ]
    }));
    for (const h of HOURS) {
      const hr = dayRecs.filter(r => Number(r.hora_bloque) === h);
      const hL = sumBy(hr, 'Ligeros', aggregator);
      const hP = sumBy(hr, 'Pesados', aggregator);
      const hM = sumBy(hr, 'M2', aggregator);
      rows.push(new TableRow({
        children: [
          tableCell(h),
          tableCell(hL),
          tableCell(hP),
          tableCell(hM),
          tableCell(hL+hP+hM)
        ]
      }));
    }
  }

  rows.push(new TableRow({
    children: [
      tableCell('Total general', { bold: true, shade: 'FFF2CC' }),
      tableCell(gL, { bold: true, shade: 'FFF2CC' }),
      tableCell(gP, { bold: true, shade: 'FFF2CC' }),
      tableCell(gM, { bold: true, shade: 'FFF2CC' }),
      tableCell(gL+gP+gM, { bold: true, shade: 'FFF2CC' })
    ]
  }));

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows
  });
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

// Tabla detalle: un registro por fila con todas las columnas operativas.
// Refleja el reporte histórico de muestra (Id, Caseta, Sentido, Fecha,
// Hora de Paso, Placa Principal, Tipo de Vehículo, N° Ejes, Placa Semi
// Remolque, N° Ejes, Placa Semi-Remolque, N° Ejes, N° Total de Ejes).
function detailTable(records) {
  const head = (txt) => tableCell(txt, { bold: true, shade: '1F4E78', color: 'FFFFFF', size: 16 });
  const rows = [
    new TableRow({
      tableHeader: true,
      children: [
        head('Id'), head('Caseta'), head('Sentido'), head('Fecha'),
        head('Hora de Paso'), head('Placa Principal'), head('Tipo de Vehículo'),
        head('N° Ejes'), head('Placa Semi Remolque'), head('N° Ejes'),
        head('Placa Semi-Remolque'), head('N° Ejes'), head('N° Total de Ejes')
      ]
    })
  ];
  const cell = (v) => tableCell(v == null ? '' : v, { size: 16 });
  let i = 1;
  for (const r of (records || [])) {
    const hp = String(r.hora_paso || '').slice(0, 5);
    rows.push(new TableRow({
      children: [
        cell(i++),
        cell(r.caseta || ''),
        cell(r.sentido || ''),
        cell(formatDate(r.fecha)),
        cell(hp),
        cell(r.placa_principal || ''),
        cell(r.tipo_vehiculo || ''),
        cell(r.ejes_principal != null ? r.ejes_principal : ''),
        cell(r.placa_semi1 || ''),
        cell(r.ejes_semi1 ? r.ejes_semi1 : ''),
        cell(r.placa_semi2 || ''),
        cell(r.ejes_semi2 ? r.ejes_semi2 : ''),
        cell(r.total_ejes != null ? r.total_ejes : '')
      ]
    }));
  }
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows });
}

function formatDate(yyyymmdd) {
  if (!yyyymmdd) return '';
  const m = String(yyyymmdd).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return yyyymmdd;
  return `${m[3]}/${m[2]}/${m[1]}`;
}

const SPANISH_MONTHS = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','setiembre','octubre','noviembre','diciembre'];
function formatLongDate(value) {
  if (!value) return '__ de __________ del ____';
  // Acepta Date (lo que devuelve mysql2 para columnas DATE) o string.
  // String(new Date(...)) en es-PE produce "Thu Jan 22 2026 ...", por eso
  // primero normalizamos a YYYY-MM-DD.
  let s;
  if (value instanceof Date && !isNaN(value)) {
    // Para columnas DATE de MySQL, el driver devuelve un Date a medianoche UTC.
    // En zonas horarias negativas (Lima = UTC-5) los getters locales devuelven
    // el día anterior, por eso usamos UTC para preservar la fecha real.
    const y  = value.getUTCFullYear();
    const mo = String(value.getUTCMonth() + 1).padStart(2, '0');
    const d  = String(value.getUTCDate()).padStart(2, '0');
    s = `${y}-${mo}-${d}`;
  } else {
    s = String(value).slice(0, 10);
  }
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return s;
  const day = parseInt(m[3], 10);
  const month = SPANISH_MONTHS[parseInt(m[2], 10) - 1] || '';
  return `${day} de ${month} del ${m[1]}`;
}

function uppercaseClean(s) {
  return String(s || '').toUpperCase().replace(/^UNIDAD DE PEAJE\s+/, '').replace(/^CONCESIONARIA\s+/, '');
}

// ── Bloque: encabezado institucional centrado (replica el del Excel) ──────

function institutionalHeader({ unitLabel, concession, periodLabel, tableTitle }) {
  const blocks = [];
  blocks.push(P('Reporte de Muestra de Flujo Vehicular Relevada en campo', { align: AlignmentType.CENTER, bold: true, size: 22, afterSpacing: 60 }));
  blocks.push(P(`correspondiente al ${periodLabel || ''}`, { align: AlignmentType.CENTER, italic: true, size: 22, afterSpacing: 60 }));
  blocks.push(P(unitLabel || '',  { align: AlignmentType.CENTER, bold: true, size: 22, afterSpacing: 60 }));
  blocks.push(P(concession || '', { align: AlignmentType.CENTER, size: 22, afterSpacing: 200 }));
  if (tableTitle) blocks.push(P(tableTitle, { align: AlignmentType.LEFT, bold: true, size: 22, afterSpacing: 120 }));
  return blocks;
}

// ── Documento principal ───────────────────────────────────────────────────

export async function buildReportBuffer({ unitLabel, concession, periodLabel, records, directions, runSummary, incidentsSummary, sampleInfo, concessionMeta, stations, includeDetailTable, detailLimit }) {
  const concName = uppercaseClean(concession);
  // Lista de peajes a iterar. Si no se pasa `stations`, se construye uno solo
  // a partir de los parámetros legacy (compatibilidad hacia atrás).
  const stationList = (Array.isArray(stations) && stations.length)
    ? stations.map(s => ({
        label: s.label || s.name || unitLabel || '',
        records: s.records || [],
        directions: s.directions || directions || [],
        sampleInfo: s.sampleInfo || null,
        photo: s.photo, photo_mime: s.photo_mime,
        map:   s.map,   map_mime:   s.map_mime
      }))
    : [{
        label: unitLabel || '',
        records: records || [],
        directions: directions || [],
        sampleInfo: sampleInfo || null,
        photo: (concessionMeta || {}).photo, photo_mime: (concessionMeta || {}).photo_mime,
        map:   (concessionMeta || {}).map,   map_mime:   (concessionMeta || {}).map_mime
      }];
  // Separar peajes regulares de unidades de conteo.
  const isConteoStation = (st) => /CONTEO|TICLIO/.test(uppercaseClean(st.label || ''));
  const peajeStations  = stationList.filter(s => !isConteoStation(s));
  const conteoStations = stationList.filter(s =>  isConteoStation(s));
  // Orden en el documento: primero peajes, luego conteos
  const orderedStations = [...peajeStations, ...conteoStations];

  // Para las páginas globales (intro, títulos) se usan los datos del primer peaje.
  const firstSt = stationList[0];
  const dirs = (firstSt.directions && firstSt.directions.length ? firstSt.directions : ['Sentido único']).slice(0, 4);
  const unitName = uppercaseClean(firstSt.label || unitLabel);
  // Detectar si es Unidad de Conteo (vs Peaje) por nombre.
  const isConteo = /CONTEO|TICLIO/.test(unitName);

  // Meses del trimestre para el texto de la sección complementaria.
  function quarterMonths(pl) {
    const l = (pl || '').toLowerCase();
    if (/primer/i.test(l))  return 'Enero a Marzo';
    if (/segundo/i.test(l)) return 'Abril a Junio';
    if (/tercer/i.test(l))  return 'Julio a Septiembre';
    if (/cuarto/i.test(l))  return 'Octubre a Diciembre';
    return null;
  }
  const quarterMonthsText = quarterMonths(periodLabel);
  // Nombre corto del peaje/conteo sin el prefijo institucional.
  const unitShort = unitName
    .replace(/^UNIDAD DE (PEAJE|CONTEO)\s+/i, '')
    .trim() || unitName;
  const meta = Object.assign({
    legal_name: null, project_description: null, invitation_date: null, carta_number: null
  }, concessionMeta || {});
  // Fechas únicas globales: unión de fechas de TODOS los peajes (para los textos
  // introductorios). Cada peaje recalcula sus propias fechas en su bloque.
  const allRecords = stationList.flatMap(s => s.records || []);
  const fechasUnicas = Array.from(new Set(allRecords.map(r => r.fecha).filter(Boolean))).sort();
  const fechaIni = fechasUnicas[0] || '';
  const fechaFin = fechasUnicas[fechasUnicas.length - 1] || '';
  // Texto legible con las fechas reales: un día, dos días o un rango.
  let fechaCampoTexto = '';
  let fechaCampoFrase = ''; // versión "el día X" / "los días X y Y" / "entre los días X y Y"
  if (fechasUnicas.length === 1) {
    fechaCampoTexto = formatLongDate(fechaIni);
    fechaCampoFrase = `el día ${fechaCampoTexto}`;
  } else if (fechasUnicas.length === 2) {
    fechaCampoTexto = `${formatLongDate(fechaIni)} y ${formatLongDate(fechaFin)}`;
    fechaCampoFrase = `los días ${fechaCampoTexto}`;
  } else if (fechasUnicas.length > 2) {
    fechaCampoTexto = `${formatLongDate(fechaIni)} al ${formatLongDate(fechaFin)}`;
    fechaCampoFrase = `entre el ${formatLongDate(fechaIni)} y el ${formatLongDate(fechaFin)}`;
  }
  // Helper: construye sampleInfo por peaje a partir de sus propios records.
  function buildSampleInfo(st) {
    if (st.sampleInfo) return st.sampleInfo;
    const fs = Array.from(new Set((st.records || []).map(r => r.fecha).filter(Boolean))).sort();
    const fi = fs[0] || '';
    const ff = fs[fs.length - 1] || '';
    return {
      ubicacion: '',
      fechaCampo: fs.length === 1
        ? formatDate(fi)
        : (fs.length ? `${formatDate(fi)} – ${formatDate(ff)}` : ''),
      turno: '08:00 – 20:00',
      sentidoCirc: 'Ambos sentidos',
      garitas: 'Todas'
    };
  }
  // Compat: muestraInfo del primer peaje, usado por textos legacy.
  const muestraInfo = sampleInfo || buildSampleInfo(firstSt);

  const children = [];

  // ─── PÁGINA 2: MUESTRA + CONSIDERACIONES ─────────────────────────────────
  // (Bloque institucional ahora va en el Header de la sección — ver más abajo.)

  // Año a partir de periodLabel
  const yearMatch = String(periodLabel || '').match(/\d{4}/);
  const year = yearMatch ? yearMatch[0] : new Date().getFullYear();
  const lowerPeriod = String(periodLabel || '').toLowerCase();
  const invDateText = formatLongDate(meta.invitation_date);
  const cartaText = meta.carta_number || '____________';
  const legalName = (meta.legal_name || concName).toUpperCase();

  if (isConteo) {
    // ── Plantilla COMPLEMENTARIA para Unidades de Conteo ───────────────
    children.push(H('INFORME DE RELEVAMIENTO DE CAMPO COMPLEMENTARIO', 1,
      { align: AlignmentType.LEFT, color: '000000', size: 24 }));
    const unitTitle = unitShort.charAt(0) + unitShort.slice(1).toLowerCase();
    children.push(P(
      `Con fecha {{FECHA_INICIO_CONTROL}}, el CONCESIONARIO dio inicio al control del flujo ` +
      `vehicular en la Unidad de conteo ${unitTitle} ubicado en el {{KM_UBICACION}}; la cual ` +
      `deberá entrar en operación como unidad de Peaje; una vez que las obras descritas en el ` +
      `Apéndice 6 del Anexo XII del Contrato de Concesión hayan sido concluidas y recepcionadas ` +
      `por el CONCEDENTE.`
    ));
    children.push(P(
      `En tal sentido, en el contrato de locación de servicio suscrita entre el CONCESIONARIO y ` +
      `el Auditor de Tráfico, se acordó incluir tanto en las actividades de campo como en el ` +
      `Informe de Relevamiento de campo, a la Unidad de Conteo de ${unitTitle}, suscribiendo las ` +
      `actividades al Manual de Selección de la Empresa Auditora de Tráfico Vehicular.`
    ));
    children.push(P(
      `Por lo que el presente informe de Relevamiento de campo, a solicitud del CONCESIONARIO ` +
      `contiene la información de relevamiento de la primera muestra de campo en la Unidad de ` +
      `Conteo Vehicular ${unitTitle} del ${lowerPeriod || 'período correspondiente'}${quarterMonthsText ? ' (' + quarterMonthsText + ')' : ''}.`
    ));
    children.push(P(
      `Dicha información, que de manera posterior será contrastada para su verificación y para ` +
      `los fines que el concesionario crea conveniente. En la Tabla 2 se detalla las fechas ` +
      `realizadas en la unidad de Conteo ${unitTitle}.`
    ));
  } else {
    // ── Plantilla estándar para Unidades de Peaje ──────────────────────
    children.push(H('MUESTRA DE FLUJO VEHICULAR RELEVADA DE CAMPO', 1,
      { align: AlignmentType.CENTER, color: '1F4E78', size: 26 }));

    children.push(P(
      `Para el año ${year}, OSITRAN, elaboró el Manual de Procedimiento de Selección para la ` +
      'Contratación de la Empresa Auditora de Tráfico Vehicular, en el cual se describen las ' +
      'actividades mínimas que deberá cumplir la empresa auditora de tráfico vehicular que ' +
      'tendrá a cargo la elaboración del Informe Anual de Auditoría de Flujo vehicular.'
    ));
    children.push(P(
      `Con fecha ${invDateText}, CIDATT Consultoría S. A. fue invitada mediante Carta N° ${cartaText}, ` +
      `por la empresa ${legalName} a presentar su propuesta técnica y económica, para participar ` +
      'del procedimiento de selección para la Contratación de la Empresa Auditora de Tráfico Vehicular.'
    ));
    children.push(P(
      'En el proceso de selección, los criterios de evaluación técnica y económica determinaron, ' +
      'que, CIDATT Consultoría S.A. sea la empresa auditora contratada por el CONCESIONARIO, previa ' +
      'opinión favorable del REGULADOR para llevar a cabo las actividades acordes con el objetivo del ' +
      'proceso de selección.'
    ));
    const projectInline = meta.project_description
      ? `ubicadas a lo largo del proyecto ${meta.project_description.replace(/\s*[-–]\s*/g, ' – ')}`
      : `ubicadas a lo largo del proyecto`;
    children.push(P(
      'De acuerdo a lo solicitado en los lineamientos mínimos establecidos para la realización de las ' +
      'actividades de verificación, y conforme a las actividades propuestas por CIDATT y aprobadas por ' +
      'el CONCESIONARIO y el REGULADOR se ha realizado las actividades de recopilación de una muestra ' +
      `de flujo vehicular correspondiente al ${lowerPeriod || 'período correspondiente'}, del flujo ` +
      `vehicular que transitó en las unidades de peaje ${projectInline} administrado por ${concName}, ` +
      'con el fin de verificar los flujos vehiculares y el ingreso efectivo recaudado.'
    ));
  }

  children.push(H('CONSIDERACIONES PARA EL ANÁLISIS DE LA MUESTRA', 1, { align: AlignmentType.LEFT, color: '1F4E78', size: 24 }));
  children.push(P(
    'La muestra relevada en campo, es la que se adjunta en el presente Informe de Relevamiento ' +
    'de Campo, cuyo objetivo es reportar al REGULADOR la información visualizada, la cual está ' +
    'sujeta a revisión, análisis y posterior determinación de resultados en el Informe Anual de ' +
    'Auditoría. Por lo mismo, en el contenido de la muestra relevada se pueden encontrar ' +
    'discrepancias entre los ejes registrados por el auditor y los ejes registrados por el ' +
    'CONCESIONARIO en su sistema de control y cobro de peaje.'
  ));
  children.push(P(
    'Las posibles discrepancias que se puedan generar son por diversos motivos, entre los más ' +
    'reincidentes de acuerdo con la experiencia del Auditor: i) la desincronización entre el ' +
    'registro horario automático del sistema de control y cobro de peaje y el registro horario ' +
    'manual realizado en el formato durante la toma de la muestra, estas variaciones pueden ' +
    'distar en minutos y la acumulación de ellos generan diferencias en los resúmenes por horas, ' +
    'los que a su vez pudieran generar casos de inclusión y/o exclusión de algunos registros ' +
    'entre un turno de operación y otro; ii) posibles errores de visualización debido a los ejes ' +
    'levantados en los vehículos de carga, entre otros.'
  ));
  children.push(P(
    `En cumplimiento de los plazos establecidos en el contrato firmado entre el CONCESIONARIO y ` +
    `el AUDITOR, se presenta el Informe de Relevamiento de Campo de la muestra de flujo vehicular ` +
    `realizada ${fechaCampoFrase || 'en la fecha indicada'} ` +
    `correspondiente al ${periodLabel || ''}.`
  ));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── PÁGINA 3: Tabla resumen de la muestra ───────────────────────────────

  children.push(P('En la siguiente tabla se detalla la información de la muestra relevada en campo:'));
  children.push(P('Tabla 1: Tamaño de la muestra', { bold: true, size: 22, afterSpacing: 80 }));

  // Una fila por peaje (multi-peaje en serie).
  const sampleRows = [
    new TableRow({
      tableHeader: true,
      children: [
        tableCell('Nº',                 { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Unidad de Peaje',    { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Ubicación',          { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Fecha de Campo',     { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Turno',              { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Sentido de Circulación', { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
        tableCell('Garitas de Peaje',   { bold: true, shade: '1F4E78', color: 'FFFFFF' })
      ]
    })
  ];
  // Tabla 1: solo peajes regulares (la Unidad de Conteo aparece en su sección complementaria).
  const tabla1Stations = peajeStations.length > 0 ? peajeStations : stationList;
  tabla1Stations.forEach((st, idx) => {
    const si = buildSampleInfo(st);
    const stName = uppercaseClean(st.label);
    sampleRows.push(new TableRow({
      children: [
        tableCell(String(idx + 1)),
        tableCell(stName),
        tableCell(si.ubicacion || '—'),
        tableCell(si.fechaCampo || '—'),
        tableCell(si.turno || '—'),
        tableCell(si.sentidoCirc || 'Ambos sentidos'),
        tableCell(si.garitas || 'Todas')
      ]
    }));
  });
  children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: sampleRows }));
  children.push(P(''));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── BLOQUE POR PEAJE (en serie) ─────────────────────────────────────────
  // Para cada peaje del array stationList se genera:
  //   1) Portada con nombre del peaje + foto + mapa
  //   2) Tabla 1 (vehículos) por sentido
  //   3) Tabla 2 (ejes) por sentido
  //   4) Tabla detalle (un registro por fila)
  // Entre peajes se intercala un PageBreak.
  const toBuf = (v) => (v && Buffer.isBuffer(v)) ? v : (v ? Buffer.from(v) : null);
  const sniff = (buf) => {
    if (!buf || buf.length < 8) return null;
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return 'png';
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'jpg';
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) return 'gif';
    if (buf[0] === 0x42 && buf[1] === 0x4D) return 'bmp';
    return null;
  };

  for (let stIdx = 0; stIdx < orderedStations.length; stIdx++) {
    const st = orderedStations[stIdx];
    const stIsConteo = isConteoStation(st);
    const stLabel = st.label || '';
    const stDirs = (st.directions && st.directions.length ? st.directions : ['Sentido único']).slice(0, 4);

    // Si es una unidad de conteo dentro de un documento multi-peaje, insertar sección complementaria.
    if (stIsConteo && stationList.length > 1) {
      children.push(new Paragraph({ children: [new PageBreak()] }));
      children.push(H('INFORME DE RELEVAMIENTO DE CAMPO COMPLEMENTARIO', 1,
        { align: AlignmentType.LEFT, color: '000000', size: 24 }));
      const stShortConteo = uppercaseClean(stLabel).replace(/^UNIDAD DE (PEAJE|CONTEO)\s+/i, '').trim();
      const stShortLower  = stShortConteo.charAt(0) + stShortConteo.slice(1).toLowerCase();
      const monthsText = quarterMonthsText ? ` (${quarterMonthsText})` : '';
      children.push(P(
        `Con fecha {{FECHA_INICIO_CONTROL}}, el CONCESIONARIO dio inicio al control del flujo ` +
        `vehicular en la Unidad de conteo ${stShortLower} ubicado en el {{KM_UBICACION}}; la cual ` +
        `deberá entrar en operación como unidad de Peaje; una vez que las obras descritas en el ` +
        `Apéndice 6 del Anexo XII del Contrato de Concesión hayan sido concluidas y recepcionadas ` +
        `por el CONCEDENTE.`
      ));
      children.push(P(
        `En tal sentido, en el contrato de locación de servicio suscrita entre el CONCESIONARIO y ` +
        `el Auditor de Tráfico, se acordó incluir tanto en las actividades de campo como en el ` +
        `Informe de Relevamiento de campo, a la Unidad de Conteo de ${stShortLower}, suscribiendo las ` +
        `actividades al Manual de Selección de la Empresa Auditora de Tráfico Vehicular.`
      ));
      children.push(P(
        `Por lo que el presente informe de Relevamiento de campo, a solicitud del CONCESIONARIO ` +
        `contiene la información de relevamiento de la primera muestra de campo en la Unidad de ` +
        `Conteo Vehicular ${stShortLower} del ${lowerPeriod || 'período correspondiente'}${monthsText}.`
      ));
      children.push(P(
        `Dicha información, que de manera posterior será contrastada para su verificación y para ` +
        `los fines que el concesionario crea conveniente. En la Tabla 2 se detalla las fechas ` +
        `realizadas en la unidad de Conteo ${stShortLower}.`
      ));
      // Tabla Nº | Unidad de Peaje | Ubicación | Fecha de Campo | Turno | Sentido | Garitas
      const conteoSI = buildSampleInfo(st);
      const conteoRows = [
        new TableRow({
          tableHeader: true,
          children: [
            tableCell('Nº',                     { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Unidad de Peaje',         { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Ubicación',               { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Fecha de Campo',          { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Turno',                   { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Sentido de Circulación',  { bold: true, shade: '1F4E78', color: 'FFFFFF' }),
            tableCell('Garitas de Peaje',        { bold: true, shade: '1F4E78', color: 'FFFFFF' })
          ]
        }),
        new TableRow({
          children: [
            tableCell('1'),
            tableCell(stShortConteo.charAt(0) + stShortConteo.slice(1).toLowerCase()),
            tableCell(conteoSI.ubicacion || '—'),
            tableCell(conteoSI.fechaCampo || '—'),
            tableCell(conteoSI.turno || '—'),
            tableCell(conteoSI.sentidoCirc || 'Ambos sentidos'),
            tableCell(conteoSI.garitas || 'Todas')
          ]
        })
      ];
      children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: conteoRows }));
      children.push(P(''));
    }
    const stRecords = st.records || [];
    const stSample = buildSampleInfo(st);

    // (1) Portada de la unidad
    children.push(P('AUDITORIA DE FLUJO VEHICULAR A LA',
      { align: AlignmentType.CENTER, bold: true, size: 28, color: '1F4E78', beforeSpacing: 1200, afterSpacing: 80 }));
    children.push(P(stLabel.toUpperCase(),
      { align: AlignmentType.CENTER, bold: true, size: 32, color: '1F4E78', afterSpacing: 600 }));
    if (stSample.ubicacion) {
      children.push(P(stSample.ubicacion, { align: AlignmentType.CENTER, italic: true, size: 24 }));
    }

    // Tabla 1×2 con foto del peaje + mapa (formato detectado por bytes mágicos).
    const photoBuf = toBuf(st.photo);
    const mapBuf   = toBuf(st.map);
    const photoFmt = sniff(photoBuf);
    const mapFmt   = sniff(mapBuf);
    if ((photoBuf && photoFmt) || (mapBuf && mapFmt)) {
      const imgCell = (buf, fmt, label) => {
        const run = (buf && fmt)
          ? imageRun(buf, { width: 280, height: 200, type: fmt, label })
          : new TextRun({ text: '', size: 20 });
        return new TableCell({
          width: { size: 50, type: WidthType.PERCENTAGE },
          verticalAlign: VerticalAlign.CENTER,
          margins: { top: 80, bottom: 80, left: 80, right: 80 },
          children: [ new Paragraph({ alignment: AlignmentType.CENTER, children: [run] }) ]
        });
      };
      children.push(new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [ new TableRow({ children: [ imgCell(photoBuf, photoFmt, `foto_peaje_${stIdx + 1}`), imgCell(mapBuf, mapFmt, `mapa_peaje_${stIdx + 1}`) ] }) ]
      }));
    }
    children.push(new Paragraph({ children: [new PageBreak()] }));

    // (2) Tabla 1 (vehículos) por sentido
    for (let i = 0; i < stDirs.length; i++) {
      const dir = stDirs[i];
      institutionalHeader({
        unitLabel: stLabel, concession, periodLabel,
        tableTitle: 'Tabla 1: Resumen de total de vehículos por hora según tipo y sentido de control'
      }).forEach(p => children.push(p));
      children.push(P([
        new TextRun({ text: 'Sentido: ', bold: true, font: 'Arial', size: 22 }),
        new TextRun({ text: dir, font: 'Arial', size: 22 })
      ], { align: AlignmentType.LEFT, afterSpacing: 120 }));
      children.push(pivotTable({
        records: stRecords.filter(r => (r.sentido || '') === dir),
        aggregator: 'count'
      }));
      children.push(P('Elaboración: SGPT-CIDATT Consultoría S.A.', { align: AlignmentType.CENTER, italic: true, size: 16, color: '6B7280', beforeSpacing: 200 }));
      children.push(new Paragraph({ children: [new PageBreak()] }));
    }

    // (3) Tabla 2 (ejes) por sentido
    for (let i = 0; i < stDirs.length; i++) {
      const dir = stDirs[i];
      institutionalHeader({
        unitLabel: stLabel, concession, periodLabel,
        tableTitle: 'Tabla 2: Resumen de total de ejes por hora según tipo y sentido de control'
      }).forEach(p => children.push(p));
      children.push(P([
        new TextRun({ text: 'Sentido: ', bold: true, font: 'Arial', size: 22 }),
        new TextRun({ text: dir, font: 'Arial', size: 22 })
      ], { align: AlignmentType.LEFT, afterSpacing: 120 }));
      children.push(pivotTable({
        records: stRecords.filter(r => (r.sentido || '') === dir),
        aggregator: 'axles'
      }));
      children.push(P('Elaboración: SGPT-CIDATT Consultoría S.A.', { align: AlignmentType.CENTER, italic: true, size: 16, color: '6B7280', beforeSpacing: 200 }));
      children.push(new Paragraph({ children: [new PageBreak()] }));
    }

    // (4) Tabla detalle (registro por fila)
    if (includeDetailTable !== false) {
      const isTruncated = detailLimit && stRecords.length > detailLimit;
      const detailRecs  = isTruncated ? stRecords.slice(0, detailLimit) : stRecords;
      institutionalHeader({
        unitLabel: stLabel, concession, periodLabel,
        tableTitle: null
      }).forEach(p => children.push(p));
      children.push(P('Reporte de Muestra de Flujo Vehicular Relevada en campo',
        { align: AlignmentType.CENTER, bold: true, italic: true, size: 22, afterSpacing: 120 }));
      if (isTruncated) {
        children.push(P(
          `Nota: Se muestran los primeros ${detailLimit.toLocaleString('es-PE')} registros de ${stRecords.length.toLocaleString('es-PE')} totales. El detalle completo está disponible en el Word individual de esta unidad.`,
          { italic: true, color: '6B7280', size: 18, afterSpacing: 120 }
        ));
      }
      children.push(detailTable(detailRecs));
      children.push(P('Elaboración: SGPT-CIDATT Consultoría S.A.', { align: AlignmentType.CENTER, italic: true, size: 16, color: '6B7280', beforeSpacing: 200 }));
    }

    // Salto de página entre peajes.
    if (stIdx < stationList.length - 1) {
      children.push(new Paragraph({ children: [new PageBreak()] }));
    }
  }

  // ─── (Sección "Observaciones del Procesamiento" eliminada por solicitud) ─

  const doc = new Document({
    creator: 'CIDATT',
    title: `Informe — ${unitLabel || ''}`,
    description: `Informe de relevamiento ${periodLabel || ''}`,
    styles: {
      default: {
        document: { run: { font: 'Arial', size: 22 } }
      }
    },
    sections: [
      // ── Sección 1: PORTADA con fondo azul a página completa ────────────
      {
        properties: {
          page: {
            size: { width: 11906, height: 16838 }, // A4 en twips
            margin: { top: 0, bottom: 0, left: 0, right: 0, header: 0, footer: 0, gutter: 0 }
          }
        },
        children: buildCoverChildren({ concName, unitLabel, periodLabel, meta })
      },
      // ── Sección 2: Resto del informe con márgenes normales ─────────────
      {
        properties: {
          page: { margin: { top: 1440, bottom: 720, left: 1080, right: 1080, header: 720, footer: 720 } }
        },
        headers: {
          default: new Header({
            children: [
              P('Auditoría de Flujo Vehicular a la Concesionaria ' + concName,
                { align: AlignmentType.CENTER, bold: true, size: 18, color: '6B7280', afterSpacing: 20 }),
              P('Muestra de Flujo Vehicular Relevada de Campo',
                { align: AlignmentType.CENTER, italic: true, size: 18, color: '6B7280', afterSpacing: 0 })
            ]
          })
        },
        footers: {
          default: new Footer({
            children: [
              new Table({
                width: { size: 100, type: WidthType.PERCENTAGE },
                borders: NO_BORDER,
                rows: [
                  new TableRow({ children: [
                    new TableCell({ width: { size: 33, type: WidthType.PERCENTAGE }, borders: NO_BORDER,
                      children: [ P('OSITRAN', { align: AlignmentType.LEFT,   bold: true, size: 18, color: '1F4E78', afterSpacing: 0 }) ] }),
                    new TableCell({ width: { size: 34, type: WidthType.PERCENTAGE }, borders: NO_BORDER,
                      children: [ P('CIDATT',  { align: AlignmentType.CENTER, bold: true, size: 18, color: '1F4E78', afterSpacing: 0 }) ] }),
                    new TableCell({ width: { size: 33, type: WidthType.PERCENTAGE }, borders: NO_BORDER,
                      children: [ P(concName,  { align: AlignmentType.RIGHT,  bold: true, size: 18, color: '1F4E78', afterSpacing: 0 }) ] })
                  ] })
                ]
              })
            ]
          })
        },
        children
      }
    ]
  });

  return await Packer.toBuffer(doc);
}

// ── Portada con fondo azul oscuro a página completa ───────────────────────

function buildCoverChildren({ concName, unitLabel, periodLabel, meta }) {
  // Mes y año a partir de periodLabel (e.g. "Primer Trimestre del año 2026")
  const yearMatch = String(periodLabel || '').match(/\d{4}/);
  const year = yearMatch ? yearMatch[0] : '';
  const trimMonths = {
    'primer':  { label: 'ENERO – MARZO', last: 'MARZO' },
    'segundo': { label: 'ABRIL – JUNIO', last: 'JUNIO' },
    'tercer':  { label: 'JULIO – SETIEMBRE', last: 'SETIEMBRE' },
    'cuarto':  { label: 'OCTUBRE – DICIEMBRE', last: 'DICIEMBRE' }
  };
  let trimText = '';
  let lastMonth = '';
  const tm = String(periodLabel || '').toLowerCase().match(/(primer|segundo|tercer|cuarto)/);
  if (tm) {
    trimText = `${trimMonths[tm[1]].label} DEL AÑO ${year}`;
    lastMonth = trimMonths[tm[1]].last;
  }

  // Texto blanco helper
  const W = (text, opts = {}) => new Paragraph({
    alignment: opts.align || AlignmentType.CENTER,
    spacing: { before: opts.before || 0, after: opts.after || 0, line: opts.line || 280 },
    children: [new TextRun({
      text: String(text || ''),
      bold: opts.bold !== false,
      italics: !!opts.italic,
      color: opts.color || 'FFFFFF',
      size: opts.size || 22,
      font: 'Arial'
    })]
  });

  // Texto del título principal (con saltos de línea desde project_description o defaults)
  const projectLines = [];
  if (meta && meta.project_description) {
    // Partir por " - " o " – " o ", " manteniendo segmentos cortos
    String(meta.project_description)
      .split(/\s*[-–]\s*|,\s*/)
      .map(s => s.trim())
      .filter(Boolean)
      .forEach((seg, i, arr) => {
        if (i === 0) projectLines.push(seg.toUpperCase());
        else if (i === arr.length - 1) projectLines.push('- ' + seg.toUpperCase());
        else projectLines.push('- ' + seg.toUpperCase());
      });
  }

  // ── Logo CIDATT (sin caja celeste — el PNG ya tiene transparencia) ──────
  const cidattBoxRow = new TableRow({
    height: { value: 1800, rule: HeightRule.EXACT },
    children: [new TableCell({
      width: { size: 100, type: WidthType.PERCENTAGE },
      verticalAlign: VerticalAlign.CENTER,
      borders: NO_BORDER,
      margins: { top: 100, bottom: 100, left: 200, right: 200 },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 100, after: 0 },
          children: [logoRun('cidatt.png', 320, 120, '[ INSERTAR LOGO CIDATT ]')]
        })
      ]
    })]
  });

  const cidattTable = new Table({
    width: { size: 60, type: WidthType.PERCENTAGE },
    alignment: AlignmentType.CENTER,
    borders: NO_BORDER,
    rows: [cidattBoxRow]
  });

  // ── Cuerpo del título ───────────────────────────────────────────────────
  const titleParagraphs = [];
  titleParagraphs.push(W('INFORME DE RELEVAMIENTO DE CAMPO', { size: 24, line: 320 }));
  titleParagraphs.push(W('DE LA AUDITORÍA DE FLUJO VEHICULAR DE', { size: 24, line: 320 }));
  titleParagraphs.push(W(`${(unitLabel || '').toUpperCase()},`, { size: 24, line: 320 }));
  titleParagraphs.push(W(`CORRESPONDIENTE AL ${trimText || (periodLabel || '').toUpperCase()} PARA LA`, { size: 24, line: 320 }));
  if (projectLines.length) {
    projectLines.forEach(line => titleParagraphs.push(W(line, { size: 24, line: 320 })));
  } else {
    titleParagraphs.push(W(`CONCESIÓN DE ${concName}`, { size: 24, line: 320 }));
  }

  // ── Logo OSITRAN ────────────────────────────────────────────────────────
  const ositranBlock = new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 400, after: 400 },
    children: [logoRun('ositran.png', 180, 90, '[ INSERTAR LOGO OSITRAN ]')]
  });

  // ── Pie ────────────────────────────────────────────────────────────────
  const footerLines = [
    W(`${lastMonth || ''}${year ? ' ' + year : ''}`.trim(), { size: 18, line: 240 }),
    W('WWW.CIDATT.COM.PE', { size: 18, line: 240 }),
    W('Calle Cinco 145 Oficina 401 – San Isidro', { size: 18, italic: true, bold: false, line: 240 })
  ];

  // ── Celda de portada ────────────────────────────────────────────────────
  const coverCell = new TableCell({
    width: { size: 100, type: WidthType.PERCENTAGE },
    shading: { type: ShadingType.CLEAR, color: 'auto', fill: NAVY },
    verticalAlign: VerticalAlign.TOP,
    borders: NO_BORDER,
    margins: { top: 1200, bottom: 600, left: 800, right: 800 },
    children: [
      cidattTable,
      // Espaciado vertical entre logo y título
      W('', { line: 240 }), W('', { line: 240 }), W('', { line: 240 }),
      W('', { line: 240 }), W('', { line: 240 }), W('', { line: 240 }),
      W('', { line: 240 }), W('', { line: 240 }),
      ...titleParagraphs,
      W('', { line: 240 }),
      W('Este documento es de uso exclusivo del Concesionario', { size: 16, italic: true, bold: false, line: 240 }),
      W(`(${concName}) y el Regulador (OSITRAN).`, { size: 16, italic: true, bold: false, line: 240 }),
      ositranBlock,
      ...footerLines
    ]
  });

  const coverTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: NO_BORDER,
    rows: [new TableRow({
      // Altura ligeramente menor que la página A4 para evitar que el sectPr final
      // (párrafo vacío de cierre de sección) se vaya a una página extra en blanco.
      height: { value: 16700, rule: HeightRule.EXACT },
      children: [coverCell]
    })]
  });

  return [coverTable];
}
