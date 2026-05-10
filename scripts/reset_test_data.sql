-- =====================================================================
-- Reset de datos de prueba CIDATT
-- =====================================================================
-- CONSERVA:
--   * cidatt_auth_users        (usuarios)
--   * cidatt_auth_tokens       (sesiones de login)
--   * cidatt_concessions       (concesiones)
--   * cidatt_projects          (proyectos)
--   * cidatt_project_sites     (peajes asignados a proyecto)
--   * cidatt_toll_stations     (peajes)
--   * cidatt_toll_booths       (casetas)
--   * cidatt_user_assignments  (pool del director / casetas del coordinador)
--
-- BORRA:
--   * cidatt_vehicle_records   (registros de vehiculos)
--   * cidatt_shift_profiles    (perfiles dentro de la sesion de turno)
--   * cidatt_shift_sessions    (sesiones de turno)
--   * cidatt_device_presence   (presencia / ultimo heartbeat)
-- =====================================================================

START TRANSACTION;

SET FOREIGN_KEY_CHECKS = 0;

-- Orden: primero los que dependen de sesiones, luego sesiones.
TRUNCATE TABLE cidatt_vehicle_records;
TRUNCATE TABLE cidatt_shift_profiles;
TRUNCATE TABLE cidatt_shift_sessions;
TRUNCATE TABLE cidatt_device_presence;

SET FOREIGN_KEY_CHECKS = 1;

COMMIT;

-- Verificacion rapida
SELECT 'cidatt_vehicle_records' AS tabla, COUNT(*) AS filas FROM cidatt_vehicle_records
UNION ALL SELECT 'cidatt_shift_profiles', COUNT(*) FROM cidatt_shift_profiles
UNION ALL SELECT 'cidatt_shift_sessions', COUNT(*) FROM cidatt_shift_sessions
UNION ALL SELECT 'cidatt_device_presence', COUNT(*) FROM cidatt_device_presence
UNION ALL SELECT 'cidatt_toll_stations (conservada)', COUNT(*) FROM cidatt_toll_stations
UNION ALL SELECT 'cidatt_toll_booths   (conservada)', COUNT(*) FROM cidatt_toll_booths
UNION ALL SELECT 'cidatt_user_assignments (conservada)', COUNT(*) FROM cidatt_user_assignments
UNION ALL SELECT 'cidatt_auth_users (conservada)', COUNT(*) FROM cidatt_auth_users;
