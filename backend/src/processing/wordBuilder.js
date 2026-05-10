// Generador de informe Word (.docx) editable usando la librería `docx`.
// Estructura:
//   Portada con título + concesionaria + período
//   1. Introducción (texto plantilla editable)
//   2. Metodología (texto plantilla editable)
//   3. Tabla 1: Resumen de vehículos por hora y sentido (una tabla por sentido)
//   4. Tabla 2: Resumen de ejes por hora y sentido (una tabla por sentido)
//   5. Observaciones / incidencias (resumen del run)
//   6. Conclusiones (texto plantilla editable)

import {
  Document, Packer, Paragraph, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, TextRun, PageBreak
} from 'docx';

const HOURS = Array.from({ length: 12 }, (_, i) => i + 8);

function P(text, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { after: 160 },
    children: [new TextRun({ text: String(text || ''), bold: !!opts.bold, italics: !!opts.italic, size: opts.size || 22 })]
  });
}

function H(text, level) {
  const map = { 1: HeadingLevel.HEADING_1, 2: HeadingLevel.HEADING_2, 3: HeadingLevel.HEADING_3 };
  return new Paragraph({
    heading: map[level] || HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 120 },
    children: [new TextRun({ text: String(text), bold: true })]
  });
}

function cell(text, opts = {}) {
  return new TableCell({
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    shading: opts.shade ? { fill: opts.shade } : undefined,
    children: [new Paragraph({
      alignment: opts.align || AlignmentType.CENTER,
      children: [new TextRun({
        text: String(text == null ? '' : text),
        bold: !!opts.bold,
        color: opts.color || undefined,
        size: 20
      })]
    })]
  });
}

function pivotTable({ records, aggregator }) {
  // Encabezado
  const rows = [
    new TableRow({
      tableHeader: true,
      children: [
        cell('Fecha y Hora', { bold: true, shade: '1e3a8a', color: 'FFFFFF' }),
        cell('Ligeros',      { bold: true, shade: '1e3a8a', color: 'FFFFFF' }),
        cell('Pesados',      { bold: true, shade: '1e3a8a', color: 'FFFFFF' }),
        cell('M2',           { bold: true, shade: '1e3a8a', color: 'FFFFFF' }),
        cell('Total general',{ bold: true, shade: '1e3a8a', color: 'FFFFFF' })
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
    rows.push(new TableRow({
      children: [
        cell(fecha, { bold: true, shade: 'dbeafe' }),
        cell(dL,    { bold: true, shade: 'dbeafe' }),
        cell(dP,    { bold: true, shade: 'dbeafe' }),
        cell(dM,    { bold: true, shade: 'dbeafe' }),
        cell(dL + dP + dM, { bold: true, shade: 'dbeafe' })
      ]
    }));
    for (const h of HOURS) {
      const hr = dayRecs.filter(r => Number(r.hora_bloque) === h);
      const hL = sumBy(hr, 'Ligeros', aggregator);
      const hP = sumBy(hr, 'Pesados', aggregator);
      const hM = sumBy(hr, 'M2', aggregator);
      rows.push(new TableRow({
        children: [
          cell(h),
          cell(hL),
          cell(hP),
          cell(hM),
          cell(hL + hP + hM)
        ]
      }));
    }
  }

  rows.push(new TableRow({
    children: [
      cell('Total general', { bold: true, shade: 'fef3c7' }),
      cell(gL, { bold: true, shade: 'fef3c7' }),
      cell(gP, { bold: true, shade: 'fef3c7' }),
      cell(gM, { bold: true, shade: 'fef3c7' }),
      cell(gL + gP + gM, { bold: true, shade: 'fef3c7' })
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

function buildDirectionSection({ direction, records, aggregator, sectionLabel }) {
  const dirRecords = records.filter(r => (r.sentido || '') === direction);
  return [
    H(`${sectionLabel} — Sentido: ${direction}`, 3),
    pivotTable({ records: dirRecords, aggregator }),
    P('')
  ];
}

export async function buildReportBuffer({ unitLabel, concession, periodLabel, records, directions, runSummary, incidentsSummary }) {
  const dirs = (directions && directions.length ? directions : ['Sentido único']).slice(0, 4);

  const children = [];

  // ── Portada
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 1200, after: 240 },
    children: [new TextRun({ text: 'Reporte de Muestra de Flujo Vehicular Relevada en Campo', bold: true, size: 36 })]
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 240 },
    children: [new TextRun({ text: `Correspondiente al ${periodLabel || ''}`, italics: true, size: 26 })]
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 600, after: 120 },
    children: [new TextRun({ text: unitLabel || '', bold: true, size: 28 })]
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 600 },
    children: [new TextRun({ text: concession || '', size: 24 })]
  }));
  children.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 240 },
    children: [new TextRun({ text: 'CIDATT — Centro de Investigación y Desarrollo de Transporte Terrestre', italics: true, size: 20 })]
  }));
  children.push(new Paragraph({ children: [new PageBreak()] }));

  // ── 1. Introducción
  children.push(H('1. Introducción', 1));
  children.push(P(
    `El presente informe documenta los resultados del relevamiento de flujo vehicular ` +
    `realizado en la ${unitLabel || ''} de la ${concession || ''}, correspondiente al ` +
    `${periodLabel || ''}. La muestra fue obtenida mediante observación directa en campo ` +
    `con personal capacitado y registrada con la plataforma de relevamiento de CIDATT.`
  ));

  // ── 2. Metodología
  children.push(H('2. Metodología', 1));
  children.push(P(
    `Los datos fueron capturados por registradores ubicados en cada caseta del peaje, ` +
    `clasificando cada vehículo por tipo (Ligero, Pesado o Motocicleta M2), número de ejes ` +
    `y sentido de circulación. La información fue validada mediante el motor de procesamiento ` +
    `de la plataforma, aplicando reglas de consistencia de placas, ejes y horarios.`
  ));

  // ── 3. Tabla 1: vehículos
  children.push(H('3. Resumen de Vehículos por Hora y Sentido', 1));
  children.push(P('A continuación se presenta el resumen de la cantidad de vehículos clasificados por hora, tipo y sentido de control:'));
  for (const d of dirs) {
    for (const node of buildDirectionSection({
      direction: d, records, aggregator: 'count',
      sectionLabel: 'Tabla 1'
    })) {
      children.push(node);
    }
  }

  // ── 4. Tabla 2: ejes
  children.push(H('4. Resumen de Ejes por Hora y Sentido', 1));
  children.push(P('Total de ejes contabilizados (suma de ejes principales y ejes de semirremolques):'));
  for (const d of dirs) {
    for (const node of buildDirectionSection({
      direction: d, records, aggregator: 'axles',
      sectionLabel: 'Tabla 2'
    })) {
      children.push(node);
    }
  }

  // ── 5. Observaciones / incidencias
  children.push(H('5. Observaciones del Procesamiento', 1));
  if (runSummary) {
    const s = runSummary || {};
    children.push(P(`Total de registros procesados: ${s.total ?? records.length}.`));
    if (s.fecha_min || s.fecha_max) {
      children.push(P(`Período cubierto por los datos: ${s.fecha_min || '?'} al ${s.fecha_max || '?'}.`));
    }
    const sev = s.by_severity || {};
    children.push(P(`Incidencias detectadas: ${(sev.error || 0)} errores, ${(sev.warning || 0)} advertencias, ${(sev.info || 0)} informativas.`));
  }
  if (incidentsSummary && incidentsSummary.applied) {
    const a = incidentsSummary.applied;
    children.push(P(
      `Acciones aplicadas durante la revisión: ${a.auto_fix} auto-correcciones, ` +
      `${a.manual_edit} ediciones manuales, ${a.deleted} registros eliminados, ` +
      `${a.accepted} aceptados sin cambios, ${a.pending} pendientes.`
    ));
  }

  // ── 6. Conclusiones
  children.push(H('6. Conclusiones', 1));
  children.push(P(
    'Los resultados aquí presentados constituyen una muestra representativa del flujo vehicular ' +
    'durante el período evaluado y permiten estimar el comportamiento operacional de la unidad ' +
    'analizada. Se recomienda complementar este reporte con análisis adicionales según los ' +
    'objetivos específicos del estudio.'
  ));

  const doc = new Document({
    creator: 'CIDATT',
    title: `Informe — ${unitLabel || ''}`,
    description: `Informe de relevamiento ${periodLabel || ''}`,
    styles: {
      default: {
        document: { run: { font: 'Calibri', size: 22 } }
      }
    },
    sections: [{ children }]
  });

  return await Packer.toBuffer(doc);
}
