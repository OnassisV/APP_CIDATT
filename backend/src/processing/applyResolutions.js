// Aplica resoluciones de incidencias y overrides manuales a los registros
// crudos para producir el dataset final que va a los entregables.
//
// Reglas:
//  - resolution = 'delete' → eliminar el registro
//  - resolution = 'manual_edit' → aplicar override (campo a campo)
//  - resolution = 'auto_fix' → aplicar la corrección segura (placa_format,
//    axles_total_mismatch, time_out_of_range no modifica nada)
//  - resolution = 'accept' o 'pending' → dejar como está
//
// Devuelve { records, applied: { auto_fix, manual_edit, deleted, accepted, pending } }

import { cleanPlate, vehicleGroup } from './validator.js';

export function applyResolutions(records, incidents) {
  // Indexar incidentes por record_ref → array
  const byRef = new Map();
  for (const inc of incidents || []) {
    const ref = String(inc.ref ?? inc.record_ref ?? '');
    if (!ref) continue;
    if (!byRef.has(ref)) byRef.set(ref, []);
    byRef.get(ref).push(inc);
  }

  const applied = { auto_fix: 0, manual_edit: 0, deleted: 0, accepted: 0, pending: 0 };
  const out = [];

  for (let i = 0; i < records.length; i++) {
    const original = records[i];
    const ref = String(original.ref ?? original.id ?? (i + 1));
    const recIncidents = byRef.get(ref) || [];

    let drop = false;
    const r = { ...original };

    for (const inc of recIncidents) {
      const resolution = inc.resolution || 'pending';

      if (resolution === 'delete') {
        drop = true;
        applied.deleted++;
        break;
      }

      if (resolution === 'pending') {
        applied.pending++;
        continue;
      }

      if (resolution === 'accept') {
        applied.accepted++;
        continue;
      }

      if (resolution === 'manual_edit') {
        const ovr = inc.override || {};
        if (ovr.placa_principal != null && ovr.placa_principal !== '') r.placa_principal = cleanPlate(ovr.placa_principal);
        if (ovr.tipo_vehiculo != null && ovr.tipo_vehiculo !== '') {
          r.tipo_vehiculo = String(ovr.tipo_vehiculo).toUpperCase().trim();
          r.tipo_grupo = vehicleGroup(r.tipo_vehiculo);
        }
        if (ovr.ejes_principal != null && ovr.ejes_principal !== '') {
          const v = parseInt(ovr.ejes_principal, 10);
          if (!isNaN(v)) {
            r.ejes_principal = v;
            r.total_ejes = (r.ejes_principal || 0) + (r.ejes_semi1 || 0) + (r.ejes_semi2 || 0);
          }
        }
        applied.manual_edit++;
        continue;
      }

      if (resolution === 'auto_fix') {
        applied.auto_fix++;
        switch (inc.rule_key) {
          case 'plate_format':
            r.placa_principal = cleanPlate(r.placa_principal);
            break;
          case 'axles_total_mismatch':
            r.total_ejes = (r.ejes_principal || 0) + (r.ejes_semi1 || 0) + (r.ejes_semi2 || 0);
            break;
          case 'sentido_invalid':
            // Sin acción automática segura — se mantiene el valor.
            break;
          // El resto (plate_missing, type_unknown, date_missing, etc.) no
          // tiene auto-fix seguro: se mantienen pero quedan contabilizados.
          default:
            break;
        }
        continue;
      }
    }

    if (!drop) out.push(r);
  }

  return { records: out, applied };
}
