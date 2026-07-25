-- Las tablas nuevas de OTA no son legibles con la anon key: /api/ota/status
-- devuelve {"targets":{}} aunque las filas stable/canary existen. Mismo criterio
-- que se aplico a devices tras el incidente del 24-07: sin RLS, la anon key es
-- la barrera (vive solo en el .env del servidor).

-- 1. Diagnostico: relrowsecurity = true significa RLS activo.
SELECT relname, relrowsecurity
FROM pg_class
WHERE relname IN ('devices', 'ota_targets', 'ota_releases');

-- 2. Arreglo.
ALTER TABLE ota_targets  DISABLE ROW LEVEL SECURITY;
ALTER TABLE ota_releases DISABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE ON ota_targets  TO anon;
GRANT SELECT, INSERT, UPDATE ON ota_releases TO anon;

NOTIFY pgrst, 'reload schema';

-- 3. Comprobacion: deben salir las dos filas (stable y canary).
SELECT channel, tag, paused, updated_at FROM ota_targets ORDER BY channel;
