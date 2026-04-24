USE railway;

CREATE TABLE IF NOT EXISTS cidatt_auth_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL,
  full_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_auth_users_username (username)
);

CREATE TABLE IF NOT EXISTS cidatt_auth_tokens (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_auth_tokens_hash (token_hash),
  KEY idx_cidatt_auth_tokens_user_id (user_id),
  CONSTRAINT fk_cidatt_auth_tokens_user FOREIGN KEY (user_id) REFERENCES cidatt_auth_users (id) ON DELETE CASCADE
);

-- El usuario admin se crea desde el servidor al iniciar (con bcrypt)
-- Nota: el modelo operacional ampliado de concesiones, proyectos, peajes,
-- casetas, asignaciones multiples y presencia en tiempo real se mantiene
-- en las migraciones de runtime dentro de backend/src/server.js.

CREATE TABLE IF NOT EXISTS cidatt_shift_sessions (
  id CHAR(36) NOT NULL,
  operation_date DATE NOT NULL,
  is_multi TINYINT(1) NOT NULL DEFAULT 0,
  active_profile_index INT NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_cidatt_shift_sessions_operation_date (operation_date)
);

CREATE TABLE IF NOT EXISTS cidatt_shift_profiles (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id CHAR(36) NOT NULL,
  profile_index INT NOT NULL,
  toll_name VARCHAR(120) NOT NULL,
  booth_number VARCHAR(30) NOT NULL,
  operator_name VARCHAR(120) NOT NULL,
  direction VARCHAR(60) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_shift_profiles_session_profile (session_id, profile_index),
  CONSTRAINT fk_cidatt_shift_profiles_session FOREIGN KEY (session_id) REFERENCES cidatt_shift_sessions (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cidatt_vehicle_records (
  id CHAR(36) NOT NULL,
  session_id CHAR(36) NOT NULL,
  operation_date DATE NOT NULL,
  toll_name VARCHAR(120) NOT NULL,
  booth_number VARCHAR(30) NOT NULL,
  direction VARCHAR(60) NOT NULL,
  operator_name VARCHAR(120) NOT NULL,
  passed_at TIME NOT NULL,
  main_plate VARCHAR(20) NOT NULL,
  vehicle_type VARCHAR(20) NOT NULL,
  main_axles INT NOT NULL,
  secondary_plate VARCHAR(20) NULL,
  secondary_axles INT NOT NULL DEFAULT 0,
  total_axles INT NOT NULL,
  sync_status VARCHAR(20) NOT NULL DEFAULT 'synced',
  is_fugitive TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_cidatt_vehicle_records_session_id (session_id),
  KEY idx_cidatt_vehicle_records_operation_date (operation_date),
  KEY idx_cidatt_vehicle_records_main_plate (main_plate),
  CONSTRAINT fk_cidatt_vehicle_records_session FOREIGN KEY (session_id) REFERENCES cidatt_shift_sessions (id) ON DELETE CASCADE
);
