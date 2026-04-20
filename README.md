# RLV CIDATT

Version paralela del capturador original para migracion a Railway + MySQL, sin modificar la carpeta Pedro.

## Estructura

- `frontend/`: interfaz reutilizada y adaptada para sincronizar con una API.
- `backend/`: servicio Express preparado para Railway.
- `db/`: esquema inicial para MySQL.

## Flujo previsto

1. El operador captura datos en el frontend.
2. El navegador sigue guardando una copia local en IndexedDB.
3. El frontend intenta sincronizar turno y registros con la API.
4. El backend persiste todo en MySQL.
5. Otro equipo consulta la misma informacion centralizada.

## Arranque local

### 1. Base de datos

El esquema de `db/schema.sql` ya fue cargado en la base `railway` y crea estas tablas aisladas del resto del servicio:

- `cidatt_auth_users`
- `cidatt_auth_tokens`
- `cidatt_shift_sessions`
- `cidatt_shift_profiles`
- `cidatt_vehicle_records`

Usuario inicial sembrado:

- Usuario: `admin`
- Clave: `CIDATT2026!`

Conviene cambiar esta clave apenas el backend quede en ejecucion estable.

### 2. Backend

Dentro de `backend/`:

```bash
npm install
cp .env.example .env
npm run dev
```

El archivo `.env` ya fue creado con valores orientados a Railway. Solo falta reemplazar la password real del servicio si cambia o si prefieres usar otra conexion.

### 3. Frontend

El backend ya sirve la carpeta `frontend/`, asi que basta abrir:

```text
http://localhost:3000
```

## Despliegue en Railway

La carpeta `rlv-cidatt/` ya quedo preparada para desplegarse como un solo servicio en Railway usando:

- `Dockerfile`
- `railway.json`
- backend Express sirviendo `frontend/`

### Variables que debes configurar en Railway

- `PORT`: Railway la inyecta normalmente de forma automatica.
- `MYSQLHOST`
- `MYSQLPORT`
- `MYSQLUSER`
- `MYSQLPASSWORD`
- `MYSQLDATABASE=railway`
- `MYSQL_SSL=true`

### Pasos exactos

1. Crea un nuevo servicio en Railway a partir de este proyecto.
2. Usa como raiz del servicio la carpeta `rlv-cidatt/`.
3. Railway detectara el `Dockerfile` y construira el contenedor.
4. En Variables, carga las credenciales reales de MySQL Railway.
5. Despliega el servicio.
6. Verifica que responda `GET /api/health`.
7. Abre la URL publica del servicio y prueba login con `admin / CIDATT2026!`.

### Cambio de clave inicial

La clave sembrada sirve solo para arranque. Apenas el servicio quede arriba, cambia esa credencial directamente en MySQL con algo como:

```sql
UPDATE cidatt_auth_users
SET password_hash = SHA2('NuevaClaveSegura', 256)
WHERE username = 'admin';
```

## Estado actual

- Se creo una API base para sesiones, registros y autenticacion.
- Se adapto el frontend para login real y sincronizacion best effort.
- El esquema ya existe en la base `railway` con tablas prefijadas `cidatt_`.
- El proyecto ya esta preparado para despliegue en Railway con Docker y healthcheck.
- El original sigue intacto en `Pedro/`.

## Siguientes pasos recomendados

1. Desplegar el servicio en Railway usando la carpeta `rlv-cidatt/`.
2. Probar login con `admin / CIDATT2026!`.
3. Completar panel de consulta y reportes.
4. Endurecer sincronizacion offline y reintentos.
