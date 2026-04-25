# APP CIDATT

Aplicacion operativa para gestion de personal y registro vehicular en peajes, preparada para Railway + MySQL con frontend estatico servido por Express.

## Stack actual

- `frontend/`: HTML, CSS y JavaScript vanilla.
- `backend/`: Node.js 20 + Express.
- `db/`: esquema base y notas de persistencia.
- Persistencia central: MySQL por `mysql2`.
- Persistencia local: IndexedDB para operacion offline y cola de sincronizacion.

## Arquitectura resumida

1. El backend sirve `index.html` y `panel.html`.
2. El registrador captura datos y los guarda localmente aun sin conexion.
3. Cuando hay red, la app sincroniza sesiones, registros y presencia con la API.
4. El coordinador asigna casetas en tiempo real viendo usuarios conectados.
5. El sistema soporta hasta 2 casetas simultaneas por registrador.

## Modelo operativo actual

- Concesiones reutilizables.
- Proyectos vinculados a concesiones.
- Peajes y casetas reutilizables entre proyectos.
- Asignaciones activas por usuario, proyecto, peaje y caseta.
- Presencia por dispositivo para monitoreo online/offline.
- Registros vehiculares con soporte de `fuga`.

Nota: el modelo ampliado se crea en las migraciones runtime de `backend/src/server.js`. `db/schema.sql` se mantiene como esquema base/documental.

## Arranque local

### 1. Configurar entorno

En `backend/`:

```bash
npm install
cp .env.example .env
```

Completa `.env` con tu MySQL:

```env
PORT=3000
MYSQLHOST=...
MYSQLPORT=3306
MYSQLUSER=...
MYSQLPASSWORD=...
MYSQLDATABASE=railway
MYSQL_SSL=true
```

### 2. Ejecutar backend

```bash
npm run dev
```

Al iniciar:

- se ejecutan migraciones automaticas
- se siembran usuarios de prueba si no existen
- se sirve el frontend desde el mismo backend

### 3. Abrir la app

```text
http://localhost:3000
```

## Endpoints de verificacion

- `GET /healthz`
- `GET /api/health`

Si ambos responden bien, el servicio y la base estan disponibles.

## Usuarios de prueba sembrados

- `admin / CIDATT2026!`
- `director.test / Director2026!`
- `coord.test / Coord2026!`
- `registrador.test / Reg2026!`
- `reg2.test / Reg2026!`
- `reg3.test / Reg2026!`
- `reg4.test / Reg2026!`

## Despliegue en Railway

El proyecto ya incluye:

- `Dockerfile`
- `railway.json`
- backend sirviendo `frontend/`

### Variables requeridas

- `MYSQLHOST`
- `MYSQLPORT`
- `MYSQLUSER`
- `MYSQLPASSWORD`
- `MYSQLDATABASE`
- `MYSQL_SSL`
- `PORT` la maneja Railway normalmente

### Pasos

1. Crea un servicio nuevo desde este repositorio.
2. Usa como raiz del servicio la carpeta del proyecto.
3. Railway construira con el `Dockerfile`.
4. Configura las variables del MySQL real.
5. Despliega.
6. Valida `GET /healthz`.
7. Valida `GET /api/health`.
8. Ingresa a la URL publica y prueba login.

## Cambio de claves

Las contrasenas usan `bcrypt`, no `SHA2`.

Para generar un hash nuevo desde `backend/`:

```bash
node --input-type=module -e "import bcrypt from 'bcrypt'; bcrypt.hash('NuevaClaveSegura', 12).then(console.log)"
```

Luego actualiza la tabla:

```sql
UPDATE cidatt_auth_users
SET password_hash = 'HASH_GENERADO'
WHERE username = 'admin';
```

## Recomendacion de prueba antes de publicar

1. Crear concesion, proyecto y peaje.
2. Verificar herencia de configuracion historica.
3. Asignar un registrador a 2 casetas.
4. Probar captura normal, fuga y modo offline.
5. Verificar sincronizacion al reconectar.
6. Probar cierre individual, cierre global y cierre local.
