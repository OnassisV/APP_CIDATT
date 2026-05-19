// Motor de validación / normalización de registros para procesamiento.
// Recibe un array uniforme de registros y devuelve:
//   { records: [...] (con flags), incidents: [...], summary: {...} }
//
// Las reglas se basan en lo conversado con el director:
//  - placas mayúsculas, sin guion/espacio, formato [A-Z0-9]{5,7}
//  - tipos válidos: L, C, M2, O, PNP, A
//  - ejes según tipo (con auto-fix seguro cuando aplica)
//  - total ejes = principal + secundario
//  - duplicados exactos (placa + hora + caseta)
//  - hora fuera de rango opcional
//  - sentido válido si se pasa lista de sentidos esperados
//
// El record_ref se usa para que el frontend pueda volver a localizar la fila.

const VALID_TYPES = new Set(['L', 'C', 'M2', 'O', 'PNP', 'A']);
const TWO_AXLES_TYPES = new Set(['L', 'M2', 'PNP', 'A']);
const PLATE_RE = /^[A-Z0-9]{5,7}$/;

// Canoniza la placa: mayúsculas, sin caracteres no alfanuméricos.
export function cleanPlate(raw) {
  if (raw == null) return '';
  return String(raw).toUpperCase().trim().replace(/[^A-Z0-9]/g, '');
}

// Convierte un valor de hora variado (string HH:MM:SS, número Excel, Date) a HH:MM:SS.
export function normalizeTimeOfDay(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number') {
    // Fracción de día (formato Excel): 0.5 = 12:00:00
    const totalSec = Math.round(value * 86400);
    const h = Math.floor(totalSec / 3600) % 24;
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }
  if (value instanceof Date) {
    const h = value.getHours();
    const m = value.getMinutes();
    const s = value.getSeconds();
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }
  const str = String(value).trim();
  const m = str.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return str;
  const hh = String(Math.min(23, parseInt(m[1], 10))).padStart(2, '0');
  const mm = String(Math.min(59, parseInt(m[2], 10))).padStart(2, '0');
  const ss = String(Math.min(59, parseInt(m[3] || '0', 10))).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

// Convierte fecha variada a YYYY-MM-DD.
export function normalizeDate(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) {
    const y = value.getFullYear();
    const m = String(value.getMonth() + 1).padStart(2, '0');
    const d = String(value.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }
  if (typeof value === 'number') {
    // Fecha Excel (días desde 1899-12-30)
    const ms = Math.round((value - 25569) * 86400 * 1000);
    const dt = new Date(ms);
    return normalizeDate(dt);
  }
  const str = String(value).trim();
  // Soporta "2026-04-01", "2026/04/01", "01/04/2026"
  let m = str.match(/^(\d{4})[-/](\d{2})[-/](\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  m = str.match(/^(\d{2})[-/](\d{2})[-/](\d{4})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;
  return str;
}

// Tipo "Ligeros" / "Pesados" / "M2" derivado del tipo corto.
export function vehicleGroup(type) {
  const t = String(type || '').toUpperCase();
  if (t === 'C') return 'Pesados';
  if (t === 'M2') return 'M2';
  return 'Ligeros'; // L, PNP, A, O
}

// Núcleo de validación.
// records: [{ id, caseta, sentido, fecha, hora_paso, placa_principal, tipo_vehiculo,
//             ejes_principal, placa_semi1, ejes_semi1, placa_semi2, ejes_semi2,
//             total_ejes, hora_bloque, tipo_grupo }]
// expectedSentidos: opcional array<string> de los 2 sentidos esperados (para validar)
// dailyStartTime / dailyEndTime: opcional, HH:MM:SS para validar rango horario
export function validateRecords(records, options = {}) {
  const { expectedSentidos = null, dailyStartTime = null, dailyEndTime = null } = options;
  const incidents = [];
  const cleaned = [];
  const seen = new Map(); // dedupe key -> first index

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const ref = String(r.id != null && r.id !== '' ? r.id : i + 1);

    // Limpieza/normalización
    const placaPrincipal = cleanPlate(r.placa_principal);
    const placaSemi1 = cleanPlate(r.placa_semi1);
    const placaSemi2 = cleanPlate(r.placa_semi2);
    const tipo = String(r.tipo_vehiculo || '').toUpperCase().trim();
    const fecha = normalizeDate(r.fecha);
    const hora = normalizeTimeOfDay(r.hora_paso);
    const sentido = String(r.sentido || '').trim();
    const ejesPrincipal = parseInt(r.ejes_principal, 10) || 0;
    const ejesSemi1 = parseInt(r.ejes_semi1, 10) || 0;
    const ejesSemi2 = parseInt(r.ejes_semi2, 10) || 0;
    const totalEjesDeclarado = parseInt(r.total_ejes, 10) || 0;
    const totalEjesCalc = ejesPrincipal + ejesSemi1 + ejesSemi2;

    const out = {
      ...r,
      ref,
      placa_principal: placaPrincipal,
      placa_semi1: placaSemi1,
      placa_semi2: placaSemi2,
      tipo_vehiculo: tipo,
      fecha,
      hora_paso: hora,
      sentido,
      ejes_principal: ejesPrincipal,
      ejes_semi1: ejesSemi1,
      ejes_semi2: ejesSemi2,
      total_ejes: totalEjesDeclarado || totalEjesCalc,
      tipo_grupo: r.tipo_grupo || vehicleGroup(tipo),
      hora_bloque: r.hora_bloque != null && r.hora_bloque !== '' ? parseInt(r.hora_bloque, 10) : (hora ? parseInt(hora.substring(0, 2), 10) : null),
      _flags: []
    };

    // 1) Placa principal vacía o inválida
    if (!placaPrincipal) {
      incidents.push({ ref, rule_key: 'plate_missing', severity: 'error', payload: { campo: 'placa_principal' } });
      out._flags.push('plate_missing');
    } else if (!PLATE_RE.test(placaPrincipal)) {
      incidents.push({ ref, rule_key: 'plate_format', severity: 'warning', payload: { placa: placaPrincipal, original: r.placa_principal } });
      out._flags.push('plate_format');
    }

    // 2) Tipo desconocido
    if (!VALID_TYPES.has(tipo)) {
      incidents.push({ ref, rule_key: 'type_unknown', severity: 'error', payload: { tipo, original: r.tipo_vehiculo } });
      out._flags.push('type_unknown');
    } else {
      // 3) Ejes según tipo — solo L/M2/PNP/A tienen un número fijo (2).
      // C y O aceptan cualquier cantidad ≥ 1 (variable según el vehículo concreto).
      if (TWO_AXLES_TYPES.has(tipo) && ejesPrincipal !== 2) {
        incidents.push({ ref, rule_key: 'axles_invalid_for_type', severity: 'warning', payload: { tipo, ejes: ejesPrincipal, esperado: 2 } });
        out._flags.push('axles_invalid_for_type');
      }
    }

    // 4) Total ejes incoherente
    if (totalEjesDeclarado && totalEjesDeclarado !== totalEjesCalc) {
      incidents.push({
        ref,
        rule_key: 'axles_total_mismatch',
        severity: 'warning',
        payload: { declarado: totalEjesDeclarado, calculado: totalEjesCalc }
      });
      out._flags.push('axles_total_mismatch');
    }

    // 5) Sentido inválido
    if (expectedSentidos && expectedSentidos.length && sentido && !expectedSentidos.includes(sentido)) {
      incidents.push({ ref, rule_key: 'sentido_invalid', severity: 'warning', payload: { sentido, esperados: expectedSentidos } });
      out._flags.push('sentido_invalid');
    }

    // 6) Hora fuera de turno
    if (hora && dailyStartTime && dailyEndTime) {
      if (hora < dailyStartTime || hora > dailyEndTime) {
        incidents.push({ ref, rule_key: 'time_out_of_range', severity: 'info', payload: { hora, ventana: [dailyStartTime, dailyEndTime] } });
        out._flags.push('time_out_of_range');
      }
    }

    // 7) Fecha faltante
    if (!fecha) {
      incidents.push({ ref, rule_key: 'date_missing', severity: 'error', payload: { original: r.fecha } });
      out._flags.push('date_missing');
    }

    // 8) Duplicados exactos (placa + hora + caseta)
    const dedupeKey = `${placaPrincipal}|${hora || ''}|${r.caseta || ''}|${fecha || ''}`;
    if (placaPrincipal && hora) {
      if (seen.has(dedupeKey)) {
        incidents.push({
          ref,
          rule_key: 'duplicate_exact',
          severity: 'warning',
          payload: { placa: placaPrincipal, hora, caseta: r.caseta, fecha, primera_ocurrencia_ref: seen.get(dedupeKey) }
        });
        out._flags.push('duplicate_exact');
      } else {
        seen.set(dedupeKey, ref);
      }
    }

    cleaned.push(out);
  }

  // Resumen
  const summary = {
    total: cleaned.length,
    by_severity: { error: 0, warning: 0, info: 0 },
    by_rule: {}
  };
  for (const inc of incidents) {
    summary.by_severity[inc.severity] = (summary.by_severity[inc.severity] || 0) + 1;
    summary.by_rule[inc.rule_key] = (summary.by_rule[inc.rule_key] || 0) + 1;
  }
  // Validar fechas vs período declarado
  if (cleaned.length) {
    const fechas = cleaned.map(r => r.fecha).filter(Boolean).sort();
    summary.fecha_min = fechas[0] || null;
    summary.fecha_max = fechas[fechas.length - 1] || null;
  }

  return { records: cleaned, incidents, summary };
}

// Diccionario de etiquetas en español para mostrar al director.
export const RULE_LABELS = {
  plate_missing:           { titulo: 'Placa principal vacía', descripcion: 'No se registró la placa del vehículo principal.' },
  plate_format:            { titulo: 'Formato de placa irregular', descripcion: 'La placa no cumple el formato estándar (5 a 7 letras y números).' },
  type_unknown:            { titulo: 'Tipo de vehículo desconocido', descripcion: 'El tipo no es uno de: L, C, M2, O, PNP, A.' },
  axles_invalid_for_type:  { titulo: 'Ejes incoherentes con el tipo', descripcion: 'El número de ejes no corresponde al tipo declarado.' },
  axles_total_mismatch:    { titulo: 'Total de ejes inconsistente', descripcion: 'El total declarado no coincide con la suma principal + semi.' },
  sentido_invalid:         { titulo: 'Sentido no reconocido', descripcion: 'El sentido no figura entre los dos sentidos del peaje.' },
  time_out_of_range:       { titulo: 'Hora fuera del horario operativo', descripcion: 'El paso ocurrió fuera del rango configurado para la unidad.' },
  date_missing:            { titulo: 'Fecha faltante', descripcion: 'No se pudo determinar la fecha del paso.' },
  duplicate_exact:         { titulo: 'Registro duplicado', descripcion: 'Misma placa + hora + caseta detectada en otra fila.' }
};
