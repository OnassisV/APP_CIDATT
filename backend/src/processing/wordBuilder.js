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
  Table, TableRow, TableCell, WidthType, BorderStyle, TextRun, PageBreak,
  ShadingType
} from 'docx';

const HOURS = Array.from({ length: 12 }, (_, i) => i + 8);

// ── Helpers de párrafo / celda ────────────────────────────────────────────

function P(text, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { after: opts.afterSpacing != null ? opts.afterSpacing : 160, before: opts.beforeSpacing || 0 },
    children: (Array.isArray(text) ? text : [text]).map(t =>
      typeof t === 'string'
        ? new TextRun({ text: t, bold: !!opts.bold, italics: !!opts.italic, size: opts.size || 22, color: opts.color, font: 'Calibri' })
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
    children: [new TextRun({ text: String(text), bold: true, color: opts.color || '1F4E78', size: opts.size, font: 'Calibri' })]
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
        font: 'Calibri'
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

function formatDate(yyyymmdd) {
  if (!yyyymmdd) return '';
  const m = String(yyyymmdd).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return yyyymmdd;
  return `${m[3]}/${m[2]}/${m[1]}`;
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

export async function buildReportBuffer({ unitLabel, concession, periodLabel, records, directions, runSummary, incidentsSummary, sampleInfo }) {
  const dirs = (directions && directions.length ? directions : ['Sentido único']).slice(0, 4);
  const concName = uppercaseClean(concession);
  const unitName = uppercaseClean(unitLabel);
  const fechas = (records || []).map(r => r.fecha).filter(Boolean).sort();
  const fechaIni = fechas[0] ? formatDate(fechas[0]) : '';
  const fechaFin = fechas[fechas.length - 1] ? formatDate(fechas[fechas.length - 1]) : '';
  const muestraInfo = sampleInfo || {
    ubicacion: '',
    fechaCampo: fechaIni && fechaFin && fechaIni !== fechaFin ? `${fechaIni} – ${fechaFin}` : fechaIni,
    turno: '08:00 – 20:00',
    sentidoCirc: 'Ambos sentidos',
    garitas: 'Todas'
  };

  const children = [];

  // ─── PORTADA ─────────────────────────────────────────────────────────────
  children.push(P('Auditoría de Flujo Vehicular a la Concesionaria ' + concName,
    { align: AlignmentType.CENTER, bold: true, color: '1F4E78', size: 24, beforeSpacing: 600, afterSpacing: 80 }));
  children.push(P('Muestra de Flujo Vehicular Relevada de Campo',
    { align: AlignmentType.CENTER, italic: true, size: 22, afterSpacing: 60 }));
  children.push(P(`OSITRAN  •  CIDATT  •  ${concName}`,
    { align: AlignmentType.CENTER, bold: true, size: 22, afterSpacing: 240 }));
  children.push(P((periodLabel || '').toUpperCase(),
    { align: AlignmentType.CENTER, bold: true, size: 26, color: '1F4E78', afterSpacing: 80 }));
  children.push(P('WWW.CIDATT.COM.PE',
    { align: AlignmentType.CENTER, size: 20, afterSpacing: 40 }));
  children.push(P('Calle Cinco 145 Oficina 401 – San Isidro',
    { align: AlignmentType.CENTER, italic: true, size: 20, afterSpacing: 600 }));

  children.push(P('INFORME DE RELEVAMIENTO DE CAMPO',
    { align: AlignmentType.CENTER, bold: true, size: 32, color: '1F4E78', afterSpacing: 80 }));
  children.push(P(`DE LA AUDITORÍA DE FLUJO VEHICULAR DE LA ${unitLabel || ''},`,
    { align: AlignmentType.CENTER, bold: true, size: 28, color: '1F4E78', afterSpacing: 80 }));
  children.push(P(`CORRESPONDIENTE AL ${(periodLabel || '').toUpperCase()}`,
    { align: AlignmentType.CENTER, bold: true, size: 28, color: '1F4E78', afterSpacing: 80 }));
  children.push(P(`PARA LA CONCESIÓN DE ${concName}`,
    { align: AlignmentType.CENTER, bold: true, size: 28, color: '1F4E78', afterSpacing: 600 }));

  children.push(P(`Este documento es de uso exclusivo del Concesionario (${concName}) y el Regulador (OSITRAN).`,
    { align: AlignmentType.CENTER, italic: true, size: 20, afterSpacing: 0 }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── PÁGINA 2: MUESTRA + CONSIDERACIONES ─────────────────────────────────
  children.push(P('Auditoría de Flujo Vehicular a la Concesionaria ' + concName,
    { align: AlignmentType.CENTER, bold: true, size: 18, color: '6B7280', afterSpacing: 40 }));
  children.push(P('Muestra de Flujo Vehicular Relevada de Campo',
    { align: AlignmentType.CENTER, italic: true, size: 18, color: '6B7280', afterSpacing: 40 }));
  children.push(P(`OSITRAN  CIDATT  ${concName}`,
    { align: AlignmentType.CENTER, bold: true, size: 18, color: '6B7280', afterSpacing: 240 }));

  children.push(H('MUESTRA DE FLUJO VEHICULAR RELEVADA DE CAMPO', 1, { align: AlignmentType.CENTER, color: '1F4E78', size: 26 }));
  children.push(P(
    'Para el año en curso, OSITRAN elaboró el Manual de Procedimiento de Selección para la ' +
    'Contratación de la Empresa Auditora de Tráfico Vehicular, en el cual se describen las ' +
    'actividades mínimas que deberá cumplir la empresa auditora de tráfico vehicular que ' +
    'tendrá a cargo la elaboración del Informe Anual de Auditoría de Flujo vehicular.'
  ));
  children.push(P(
    `CIDATT Consultoría S.A. fue contratada por la concesionaria ${concName}, previa opinión ` +
    'favorable del REGULADOR, para llevar a cabo las actividades acordes con el objetivo del ' +
    'proceso de selección.'
  ));
  children.push(P(
    `Conforme a las actividades propuestas por CIDATT y aprobadas por el CONCESIONARIO y el ` +
    `REGULADOR, se ha realizado las actividades de recopilación de una muestra de flujo vehicular ` +
    `correspondiente al ${periodLabel || ''}, del flujo vehicular que transitó en la ` +
    `${unitLabel || ''}, con el fin de verificar los flujos vehiculares y el ingreso efectivo recaudado.`
  ));

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
    `realizada ${muestraInfo.fechaCampo ? 'entre los días ' + muestraInfo.fechaCampo : ''} ` +
    `correspondiente al ${periodLabel || ''}.`
  ));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── PÁGINA 3: Tabla resumen de la muestra ───────────────────────────────
  children.push(P('Auditoría de Flujo Vehicular a la Concesionaria ' + concName,
    { align: AlignmentType.CENTER, bold: true, size: 18, color: '6B7280', afterSpacing: 40 }));
  children.push(P('Muestra de Flujo Vehicular Relevada de Campo',
    { align: AlignmentType.CENTER, italic: true, size: 18, color: '6B7280', afterSpacing: 40 }));
  children.push(P(`OSITRAN  CIDATT  ${concName}`,
    { align: AlignmentType.CENTER, bold: true, size: 18, color: '6B7280', afterSpacing: 240 }));

  children.push(P('En la siguiente tabla se detalla la información de la muestra relevada en campo:'));
  children.push(P('Tabla 1: Tamaño de la muestra', { bold: true, size: 22, afterSpacing: 80 }));

  const sampleTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
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
      }),
      new TableRow({
        children: [
          tableCell('1'),
          tableCell(unitName),
          tableCell(muestraInfo.ubicacion || '—'),
          tableCell(muestraInfo.fechaCampo || '—'),
          tableCell(muestraInfo.turno || '—'),
          tableCell(muestraInfo.sentidoCirc || 'Ambos sentidos'),
          tableCell(muestraInfo.garitas || 'Todas')
        ]
      })
    ]
  });
  children.push(sampleTable);
  children.push(P(''));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── PORTADA DE LA UNIDAD ────────────────────────────────────────────────
  children.push(P('AUDITORIA FLUJO VEHICULAR A LA',
    { align: AlignmentType.CENTER, bold: true, size: 28, color: '1F4E78', beforeSpacing: 1200, afterSpacing: 80 }));
  children.push(P((unitLabel || '').toUpperCase(),
    { align: AlignmentType.CENTER, bold: true, size: 32, color: '1F4E78', afterSpacing: 600 }));
  if (muestraInfo.ubicacion) {
    children.push(P(muestraInfo.ubicacion, { align: AlignmentType.CENTER, italic: true, size: 24 }));
  }
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ─── TABLA 1 (vehículos) por sentido ─────────────────────────────────────
  for (let i = 0; i < dirs.length; i++) {
    const dir = dirs[i];
    institutionalHeader({
      unitLabel, concession, periodLabel,
      tableTitle: 'Tabla 1: Resumen de total de vehículos por hora según tipo y sentido de control'
    }).forEach(p => children.push(p));
    children.push(P([
      new TextRun({ text: 'Sentido: ', bold: true, font: 'Calibri', size: 22 }),
      new TextRun({ text: dir, font: 'Calibri', size: 22 })
    ], { align: AlignmentType.LEFT, afterSpacing: 120 }));
    children.push(pivotTable({
      records: records.filter(r => (r.sentido || '') === dir),
      aggregator: 'count'
    }));
    children.push(P('SIATRA', { align: AlignmentType.CENTER, italic: true, size: 16, color: '6B7280', beforeSpacing: 200 }));
    children.push(new Paragraph({ children: [new PageBreak()] }));
  }

  // ─── TABLA 2 (ejes) por sentido ──────────────────────────────────────────
  for (let i = 0; i < dirs.length; i++) {
    const dir = dirs[i];
    institutionalHeader({
      unitLabel, concession, periodLabel,
      tableTitle: 'Tabla 2: Resumen de total de ejes por hora según tipo y sentido de control'
    }).forEach(p => children.push(p));
    children.push(P([
      new TextRun({ text: 'Sentido: ', bold: true, font: 'Calibri', size: 22 }),
      new TextRun({ text: dir, font: 'Calibri', size: 22 })
    ], { align: AlignmentType.LEFT, afterSpacing: 120 }));
    children.push(pivotTable({
      records: records.filter(r => (r.sentido || '') === dir),
      aggregator: 'axles'
    }));
    children.push(P('SIATRA', { align: AlignmentType.CENTER, italic: true, size: 16, color: '6B7280', beforeSpacing: 200 }));
    if (i < dirs.length - 1) children.push(new Paragraph({ children: [new PageBreak()] }));
  }

  // ─── Observaciones del procesamiento ────────────────────────────────────
  if (incidentsSummary && incidentsSummary.applied) {
    children.push(new Paragraph({ children: [new PageBreak()] }));
    children.push(H('Observaciones del Procesamiento', 1));
    if (runSummary) {
      const s = runSummary || {};
      children.push(P(`Total de registros procesados: ${s.total ?? records.length}.`));
      const sev = s.by_severity || {};
      children.push(P(`Incidencias detectadas: ${(sev.error || 0)} errores, ${(sev.warning || 0)} advertencias, ${(sev.info || 0)} informativas.`));
    }
    const a = incidentsSummary.applied;
    children.push(P(
      `Acciones aplicadas durante la revisión: ${a.auto_fix} auto-correcciones, ` +
      `${a.manual_edit} ediciones manuales, ${a.deleted} registros eliminados, ` +
      `${a.accepted} aceptados sin cambios, ${a.pending} pendientes.`
    ));
  }

  const doc = new Document({
    creator: 'CIDATT',
    title: `Informe — ${unitLabel || ''}`,
    description: `Informe de relevamiento ${periodLabel || ''}`,
    styles: {
      default: {
        document: { run: { font: 'Calibri', size: 22 } }
      }
    },
    sections: [{
      properties: {
        page: { margin: { top: 720, bottom: 720, left: 1080, right: 1080 } }
      },
      children
    }]
  });

  return await Packer.toBuffer(doc);
}
