USE railway;

-- Reference schema for the current MySQL backend.
-- Runtime migrations and backfills still live in backend/src/server.js.

CREATE TABLE IF NOT EXISTS cidatt_auth_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL,
  full_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','director','coordinador','registrador') NOT NULL DEFAULT 'registrador',
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

CREATE TABLE IF NOT EXISTS cidatt_concessions (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(160) NOT NULL,
  status ENUM('activa','inactiva') NOT NULL DEFAULT 'activa',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_concessions_name (name)
);

CREATE TABLE IF NOT EXISTS cidatt_projects (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL,
  description TEXT NULL,
  status ENUM('activo','pausado','cerrado') NOT NULL DEFAULT 'activo',
  start_date DATE NOT NULL,
  end_date DATE NULL,
  concession_id INT UNSIGNED NULL,
  daily_start_time TIME NULL,
  daily_end_time TIME NULL,
  max_booths_per_operator INT NOT NULL DEFAULT 2,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS cidatt_toll_stations (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  project_id INT UNSIGNED NULL,
  concession_id INT UNSIGNED NULL,
  name VARCHAR(120) NOT NULL,
  location VARCHAR(200) NULL,
  daily_start_time TIME NULL,
  daily_end_time TIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS cidatt_toll_booths (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  station_id INT UNSIGNED NOT NULL,
  code VARCHAR(30) NOT NULL,
  directions VARCHAR(200) NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_cidatt_booths_station FOREIGN KEY (station_id) REFERENCES cidatt_toll_stations (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cidatt_project_sites (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  project_id INT UNSIGNED NOT NULL,
  station_id INT UNSIGNED NOT NULL,
  linked_by BIGINT UNSIGNED NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_project_sites_project_station (project_id, station_id)
);

CREATE TABLE IF NOT EXISTS cidatt_user_assignments (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  project_id INT UNSIGNED NOT NULL,
  station_id INT UNSIGNED NULL,
  booth_id INT UNSIGNED NULL,
  assigned_by BIGINT UNSIGNED NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_cidatt_assignments_user (user_id),
  KEY idx_cidatt_assignments_project (project_id)
);

CREATE TABLE IF NOT EXISTS cidatt_shift_sessions (
  id CHAR(36) NOT NULL,
  operation_date DATE NOT NULL,
  is_multi TINYINT(1) NOT NULL DEFAULT 0,
  active_profile_index INT NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  owner_user_id BIGINT UNSIGNED NULL,
  project_id INT UNSIGNED NULL,
  station_id INT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_cidatt_shift_sessions_operation_date (operation_date),
  KEY idx_cidatt_shift_sessions_scope (project_id, station_id, status)
);

CREATE TABLE IF NOT EXISTS cidatt_shift_profiles (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id CHAR(36) NOT NULL,
  profile_index INT NOT NULL,
  toll_name VARCHAR(120) NOT NULL,
  booth_number VARCHAR(30) NOT NULL,
  operator_name VARCHAR(120) NOT NULL,
  direction VARCHAR(60) NOT NULL,
  project_id INT UNSIGNED NULL,
  station_id INT UNSIGNED NULL,
  booth_id INT UNSIGNED NULL,
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
  owner_user_id BIGINT UNSIGNED NULL,
  project_id INT UNSIGNED NULL,
  station_id INT UNSIGNED NULL,
  booth_id INT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_cidatt_vehicle_records_session_id (session_id),
  KEY idx_cidatt_vehicle_records_operation_date (operation_date),
  KEY idx_cidatt_vehicle_records_main_plate (main_plate),
  KEY idx_cidatt_vehicle_records_scope (project_id, station_id, booth_id),
  CONSTRAINT fk_cidatt_vehicle_records_session FOREIGN KEY (session_id) REFERENCES cidatt_shift_sessions (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cidatt_device_presence (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  device_id VARCHAR(120) NOT NULL,
  project_id INT UNSIGNED NULL,
  station_id INT UNSIGNED NULL,
  session_id CHAR(36) NULL,
  current_mode VARCHAR(40) NOT NULL DEFAULT 'active',
  network_status VARCHAR(20) NOT NULL DEFAULT 'online',
  context_json JSON NULL,
  last_heartbeat_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_cidatt_presence_user_device (user_id, device_id)
);
