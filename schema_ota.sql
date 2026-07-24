-- Esquema OTA v2 para SafeLock (Supabase / Postgres).
-- Ejecutar una vez en el SQL editor de Supabase, ANTES de desplegar el backend.
-- Todo es aditivo e idempotente: no rompe la flota que aún reporta con el
-- formato antiguo.

-- 0. La tabla debe existir (normalmente ya está; esto cubre un proyecto nuevo)
CREATE TABLE IF NOT EXISTS devices (
  device_id     text PRIMARY KEY,
  pihole_active boolean,
  tailscale_ip  text,
  last_seen     timestamptz,
  status        text
);

-- El upsert del backend usa on_conflict=device_id: sin restricción única
-- PostgREST responde 400 y ningún heartbeat se guarda.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE tablename = 'devices' AND indexdef LIKE '%UNIQUE%(device_id)%'
  ) THEN
    ALTER TABLE devices ADD CONSTRAINT devices_device_id_key UNIQUE (device_id);
  END IF;
END $$;

-- 1. Columnas nuevas en la tabla de dispositivos ---------------------------
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS version          text,
  ADD COLUMN IF NOT EXISTS commit_sha       text,
  ADD COLUMN IF NOT EXISTS channel          text NOT NULL DEFAULT 'stable',
  ADD COLUMN IF NOT EXISTS secret_hash      text,
  ADD COLUMN IF NOT EXISTS ota_state        text,
  ADD COLUMN IF NOT EXISTS ota_error        text,
  ADD COLUMN IF NOT EXISTS ota              jsonb,
  ADD COLUMN IF NOT EXISTS health           jsonb,
  ADD COLUMN IF NOT EXISTS migration_state  text,
  ADD COLUMN IF NOT EXISTS enrolled_at      timestamptz;

-- 2. Versión objetivo por canal --------------------------------------------
-- Estado estable de la flota: canary y stable apuntan al mismo tag. El canal
-- canary solo existe durante las horas que dura la validación de un release.
CREATE TABLE IF NOT EXISTS ota_targets (
  channel     text PRIMARY KEY,
  tag         text,
  paused      boolean NOT NULL DEFAULT false,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO ota_targets (channel, tag, paused)
VALUES ('stable', NULL, false), ('canary', NULL, false)
ON CONFLICT (channel) DO NOTHING;

-- 3. Releases publicados ----------------------------------------------------
CREATE TABLE IF NOT EXISTS ota_releases (
  tag         text PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT now(),
  status      text NOT NULL DEFAULT 'canary',  -- canary | stable | revoked
  notes       text
);

-- 4. Índices ----------------------------------------------------------------
CREATE INDEX IF NOT EXISTS devices_version_idx ON devices (version);
CREATE INDEX IF NOT EXISTS devices_channel_idx ON devices (channel);

-- 5. Poner uno o dos equipos internos en canary -----------------------------
-- Sustituir por los device_id reales de los equipos de prueba. Sin esto, el
-- canal canary no tiene a nadie y un release nunca se valida antes de ir a
-- toda la flota.
--
--   UPDATE devices SET channel = 'canary' WHERE device_id IN ('safelock-xxxxxxxxxxxx');

-- 6. Refrescar el cache de esquema de PostgREST ------------------------------
-- Sin esto la API REST puede seguir rechazando las columnas nuevas unos minutos.
NOTIFY pgrst, 'reload schema';

-- 7. Verificación -----------------------------------------------------------
-- Debe devolver las 10 columnas nuevas y las dos filas de ota_targets.
SELECT column_name FROM information_schema.columns
WHERE table_name = 'devices'
  AND column_name IN ('version','commit_sha','channel','secret_hash','ota_state',
                      'ota_error','ota','health','migration_state','enrolled_at')
ORDER BY column_name;

SELECT * FROM ota_targets;
