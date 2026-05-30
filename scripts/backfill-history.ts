#!/usr/bin/env tsx
/**
 * Netatmo Weather — historical backfill into Sowel's InfluxDB.
 *
 * For each weather equipment in Sowel's SQLite, walks the Netatmo
 * `getmeasure` API at 30-min granularity for the requested number of
 * months, aggregates the points hour-by-hour and day-by-day, and writes
 * them directly into the `sowel-hourly` (90-day retention) and
 * `sowel-daily` (5-year retention) buckets — mirroring the schema
 * produced by Sowel's own `sowel-downsample-{hourly,daily}` Flux tasks
 * (`_field` in {`mean`, `min`, `max`}, tags `equipmentId`, `alias`,
 * `category`, `zoneId`, `type`).
 *
 * The raw 7-day `sowel` bucket is intentionally **not** written: anything
 * older than 7 days would be purged immediately by the retention policy
 * and writing recent points would conflict with the live history-writer.
 *
 * Usage (from inside the Sowel container — uses /app/node_modules):
 *
 *   docker exec sowel npx tsx \
 *     /app/plugins/installed/netatmo_weather/scripts/backfill-history.ts \
 *     [months]
 *
 * `months` defaults to 12. Max 60 (5 years, hard cap matching the
 * sowel-daily retention).
 *
 * Idempotent per (equipment, alias, day): existing hourly + daily points
 * for the target window are deleted before re-writing.
 */

import Database from "better-sqlite3";
import { readFileSync, writeFileSync } from "node:fs";
import { InfluxDB, Point } from "@influxdata/influxdb-client";

// ============================================================
// Configuration
// ============================================================

const DB_PATH = process.env.SOWEL_DB_PATH ?? "/app/data/sowel.db";
const TOKEN_PATH =
  process.env.NETATMO_WEATHER_TOKENS_PATH ??
  "/app/data/netatmo-weather-tokens.json";

const NETATMO_BASE = "https://api.netatmo.com";

const monthsArg = parseInt(process.argv[2] ?? "12", 10);
if (isNaN(monthsArg) || monthsArg < 1 || monthsArg > 60) {
  console.error("Usage: backfill-history.ts <months>   (1..60, default 12)");
  process.exit(1);
}
const MONTHS = monthsArg;

// ============================================================
// SQLite — settings + equipments + bindings + devices
// ============================================================

const db = new Database(DB_PATH, { readonly: true });

function getSetting(key: string): string | undefined {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
    | { value: string }
    | undefined;
  return row?.value;
}

// Sowel resolves Influx config from env vars first (docker-compose injects
// INFLUX_URL/TOKEN/ORG/BUCKET into the container), with SQLite settings as
// a legacy fallback. Mirror that precedence so the script works inside the
// container without further configuration.
const influxUrl = process.env.INFLUX_URL ?? getSetting("history.influx.url");
const influxToken = process.env.INFLUX_TOKEN ?? getSetting("history.influx.token");
const influxOrg = process.env.INFLUX_ORG ?? getSetting("history.influx.org");
const influxBucket = process.env.INFLUX_BUCKET ?? getSetting("history.influx.bucket");
const netatmoClientId = getSetting("integration.netatmo_weather.client_id");
const netatmoClientSecret = getSetting(
  "integration.netatmo_weather.client_secret",
);
if (
  !influxUrl ||
  !influxToken ||
  !influxOrg ||
  !influxBucket ||
  !netatmoClientId ||
  !netatmoClientSecret
) {
  console.error(
    "Missing required settings (history.influx.* or integration.netatmo_weather.client_id/secret) in sowel.db",
  );
  process.exit(1);
}

interface BindingRow {
  bindingId: string;
  equipmentId: string;
  equipmentName: string;
  zoneId: string;
  alias: string;
  category: string;
  type: string;
  deviceKey: string;
  deviceName: string;
  deviceModel: string;
  sourceDeviceId: string;
}

const bindingRows = db
  .prepare(
    `SELECT
       db.id            AS bindingId,
       db.alias         AS alias,
       dd.key           AS deviceKey,
       dd.category      AS category,
       dd.type          AS type,
       dev.name         AS deviceName,
       dev.model        AS deviceModel,
       dev.source_device_id AS sourceDeviceId,
       eq.id            AS equipmentId,
       eq.name          AS equipmentName,
       eq.zone_id       AS zoneId
     FROM data_bindings db
     JOIN device_data dd ON dd.id = db.device_data_id
     JOIN devices dev    ON dev.id = dd.device_id
     JOIN equipments eq  ON eq.id = db.equipment_id
     WHERE eq.type = 'weather'
       AND dev.integration_id = 'netatmo_weather'`,
  )
  .all() as BindingRow[];

db.close();

if (bindingRows.length === 0) {
  console.error(
    "No weather equipment bound to the netatmo_weather plugin found in Sowel.",
  );
  process.exit(1);
}

// Group bindings by (equipmentId, deviceModel). One getmeasure call per
// (base device, module) tuple.
interface ModuleGroup {
  equipmentId: string;
  equipmentName: string;
  zoneId: string;
  deviceModel: string; // NAMain / Outdoor Module / Wind Gauge / Rain Gauge / Indoor Module
  sourceDeviceId: string; // module's Netatmo MAC
  baseSourceDeviceId: string; // base station's Netatmo MAC (NAMain)
  bindings: BindingRow[];
}

// Build base-station map per equipment
const baseByEquipment = new Map<string, string>();
for (const row of bindingRows) {
  if (row.deviceModel === "Indoor Station") {
    baseByEquipment.set(row.equipmentId, row.sourceDeviceId);
  }
}

// Some legacy installs may register the base under a different model name
// (older plugin versions used "NAMain" verbatim). Fall back to the first
// non-module device we see for the equipment.
function findBaseId(equipmentId: string): string {
  const known = baseByEquipment.get(equipmentId);
  if (known) return known;
  const candidates = bindingRows.filter(
    (b) => b.equipmentId === equipmentId && b.deviceModel === "Indoor Station",
  );
  if (candidates.length > 0) return candidates[0].sourceDeviceId;
  // Fall back: assume the device that has co2 + pressure (base station markers)
  const pressureBinding = bindingRows.find(
    (b) => b.equipmentId === equipmentId && b.category === "pressure",
  );
  if (pressureBinding) return pressureBinding.sourceDeviceId;
  // Last resort: pick any
  const any = bindingRows.find((b) => b.equipmentId === equipmentId);
  return any?.sourceDeviceId ?? "";
}

const groups = new Map<string, ModuleGroup>();
for (const row of bindingRows) {
  const baseId = findBaseId(row.equipmentId);
  if (!baseId) {
    console.warn(`Cannot find base station for equipment ${row.equipmentName}`);
    continue;
  }
  const key = `${row.equipmentId}|${row.sourceDeviceId}`;
  let g = groups.get(key);
  if (!g) {
    g = {
      equipmentId: row.equipmentId,
      equipmentName: row.equipmentName,
      zoneId: row.zoneId,
      deviceModel: row.deviceModel,
      sourceDeviceId: row.sourceDeviceId,
      baseSourceDeviceId: baseId,
      bindings: [],
    };
    groups.set(key, g);
  }
  g.bindings.push(row);
}

// ============================================================
// Netatmo: binding key → API "type"
// ============================================================

/** Maps the device-data `key` (or alias-stripped) to the Netatmo API `type`.
 *
 * Keys mapped to `null` are deliberately skipped — the Netatmo `getmeasure`
 * endpoint refuses some derived fields (e.g. `sum_rain_1`, `sum_rain_24`)
 * at scale=30min (the only scale we use, to align with Sowel's downsampling
 * task input). For those, the live plugin still computes the values at each
 * poll, but historical backfill is not available. */
const KEY_TO_NETATMO_TYPE: Record<string, string | null> = {
  temperature: "Temperature",
  humidity: "Humidity",
  pressure: "Pressure",
  co2: "CO2",
  noise: "Noise",
  rain: "Rain",
  sum_rain_1: null, // not retrievable at scale=30min — skipped
  sum_rain_24: null, // ditto
  wind_strength: "WindStrength",
  wind_angle: "WindAngle",
  gust_strength: "Guststrength",
  gust_angle: "GustAngle",
};

/** Same as the helper used by the UI: recover the device-data key from a
 * possibly-deduplicated alias (`temperature_2` → `temperature`). The Sowel
 * auto-binding dedup counter starts at 2, so `_1` is never a dedup tag. */
function aliasToKey(alias: string): string {
  return alias.replace(/_[2-9]\d*$/, "");
}

// ============================================================
// Netatmo OAuth (with token persistence)
// ============================================================

interface SavedTokens {
  refreshToken?: string;
  accessToken?: string;
  expiresAt?: number;
}

let tokens: SavedTokens = {};
try {
  tokens = JSON.parse(readFileSync(TOKEN_PATH, "utf-8")) as SavedTokens;
} catch {
  console.error(`Cannot read ${TOKEN_PATH}. Is the plugin configured?`);
  process.exit(1);
}
if (!tokens.refreshToken) {
  console.error(
    `${TOKEN_PATH} has no refreshToken. Re-authenticate the plugin from the Admin UI first.`,
  );
  process.exit(1);
}

async function refreshAccessToken(): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: tokens.refreshToken!,
    client_id: netatmoClientId!,
    client_secret: netatmoClientSecret!,
  });
  const res = await fetch(`${NETATMO_BASE}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`Token refresh failed: ${await res.text()}`);
  const data = (await res.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
  tokens.accessToken = data.access_token;
  tokens.refreshToken = data.refresh_token;
  tokens.expiresAt = Date.now() + data.expires_in * 1000;
  try {
    writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
  } catch (err) {
    console.warn("Failed to persist refreshed token:", err);
  }
  return data.access_token;
}

async function getAccessToken(): Promise<string> {
  if (tokens.accessToken && (tokens.expiresAt ?? 0) > Date.now() + 60_000) {
    return tokens.accessToken;
  }
  return refreshAccessToken();
}

// ============================================================
// Resolve Netatmo MACs from module_name (Sowel's sourceDeviceId)
// ============================================================
//
// The plugin upserts each Netatmo module as a Sowel device with
// `sourceDeviceId = mod.module_name` (e.g. "Outdoor Module"). The
// `getmeasure` API only accepts MAC addresses for `device_id` and
// `module_id`. We resolve the mapping by calling `getstationsdata`
// once at startup.

interface NetatmoModuleMeta {
  mac: string; // module's `_id` (= MAC address, used as module_id)
  type: string; // NAModule1 / NAModule2 / NAModule3 / NAModule4 / NAMain
  stationMac: string; // parent station's `_id`
}

async function resolveNetatmoMetas(): Promise<Map<string, NetatmoModuleMeta>> {
  const token = await getAccessToken();
  const res = await fetch(`${NETATMO_BASE}/api/getstationsdata`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error(`getstationsdata failed: ${res.status} ${await res.text()}`);
  }
  const data = (await res.json()) as {
    body?: {
      devices?: {
        _id: string;
        module_name?: string;
        station_name?: string;
        type: string;
        modules?: {
          _id: string;
          module_name?: string;
          type: string;
        }[];
      }[];
    };
  };

  const out = new Map<string, NetatmoModuleMeta>();
  const devices = data.body?.devices ?? [];
  for (const station of devices) {
    const stationMac = station._id;
    const stationName = station.module_name || station.station_name || station._id;
    out.set(stationName, { mac: stationMac, type: station.type, stationMac });
    for (const mod of station.modules ?? []) {
      const modName = mod.module_name || mod._id;
      out.set(modName, { mac: mod._id, type: mod.type, stationMac });
    }
  }
  return out;
}

// ============================================================
// InfluxDB write API (mirrors sowel-downsample tasks' schema)
// ============================================================

const hourlyBucket = `${influxBucket}-hourly`;
const dailyBucket = `${influxBucket}-daily`;

const influx = new InfluxDB({ url: influxUrl, token: influxToken });

function deleteRange(bucket: string, start: Date, stop: Date, predicate: string): Promise<Response> {
  return fetch(
    `${influxUrl}/api/v2/delete?org=${encodeURIComponent(influxOrg!)}&bucket=${encodeURIComponent(bucket)}`,
    {
      method: "POST",
      headers: {
        Authorization: `Token ${influxToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        start: start.toISOString(),
        stop: stop.toISOString(),
        predicate,
      }),
    },
  );
}

function buildAggPoint(args: {
  bucket: "hourly" | "daily";
  equipmentId: string;
  zoneId: string;
  alias: string;
  category: string;
  type: string;
  timestampSec: number;
  mean: number;
  min: number;
  max: number;
}): Point[] {
  const make = (field: "mean" | "min" | "max", value: number): Point =>
    new Point("equipment_data")
      .tag("equipmentId", args.equipmentId)
      .tag("alias", args.alias)
      .tag("category", args.category)
      .tag("type", args.type)
      .tag("zoneId", args.zoneId)
      .floatField(field, value)
      .timestamp(args.timestampSec);
  return [make("mean", args.mean), make("min", args.min), make("max", args.max)];
}

// ============================================================
// Helpers
// ============================================================

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function startOfDayUtc(d: Date): Date {
  const x = new Date(d);
  x.setUTCHours(0, 0, 0, 0);
  return x;
}

function addDays(d: Date, n: number): Date {
  const x = new Date(d);
  x.setUTCDate(x.getUTCDate() + n);
  return x;
}

function* daysBetween(from: Date, to: Date): Generator<Date> {
  let d = startOfDayUtc(from);
  const end = startOfDayUtc(to);
  while (d.getTime() < end.getTime()) {
    yield d;
    d = addDays(d, 1);
  }
}

// ============================================================
// Process one (group, day)
// ============================================================

interface DayResult {
  rawPoints: number;
  hourPoints: number;
}

async function processGroupDay(
  group: ModuleGroup,
  day: Date,
  metas: Map<string, NetatmoModuleMeta>,
): Promise<DayResult> {
  // Translate Sowel sourceDeviceId (== module_name) → Netatmo MACs.
  const moduleMeta = metas.get(group.sourceDeviceId);
  const baseMeta = metas.get(group.baseSourceDeviceId);
  if (!moduleMeta || !baseMeta) {
    throw new Error(
      `Cannot resolve MAC for module="${group.sourceDeviceId}" or base="${group.baseSourceDeviceId}" — Netatmo getstationsdata didn't return a match`,
    );
  }
  const dayStart = day;
  const dayEnd = addDays(day, 1);
  const dayStartTs = Math.floor(dayStart.getTime() / 1000);
  const dayEndTs = Math.floor(dayEnd.getTime() / 1000);

  // Build the Netatmo `type` csv from this group's bindings.
  const apiTypes: string[] = [];
  // Map: position in Netatmo response array → binding
  const positionToBinding: BindingRow[] = [];
  for (const b of group.bindings) {
    const key = aliasToKey(b.alias);
    // Two lookups because the alias may itself carry a numeric suffix that
    // looks like a dedup tag but isn't (e.g. `sum_rain_1` is a real key).
    const fromKey = key in KEY_TO_NETATMO_TYPE ? KEY_TO_NETATMO_TYPE[key] : undefined;
    const fromDeviceKey =
      b.deviceKey in KEY_TO_NETATMO_TYPE ? KEY_TO_NETATMO_TYPE[b.deviceKey] : undefined;
    // `null` is a deliberate skip (vs `undefined` = unknown key)
    const netatmoType = fromKey !== undefined ? fromKey : fromDeviceKey;
    if (!netatmoType) continue;
    apiTypes.push(netatmoType);
    positionToBinding.push(b);
  }
  if (apiTypes.length === 0) return { rawPoints: 0, hourPoints: 0 };

  const accessToken = await getAccessToken();
  const params = new URLSearchParams({
    device_id: baseMeta.mac,
    type: apiTypes.join(","),
    scale: "30min",
    optimize: "false",
    real_time: "true",
    date_begin: String(dayStartTs),
    date_end: String(dayEndTs),
  });
  // Only set module_id when the binding is on a sub-module, not the base
  if (moduleMeta.mac !== baseMeta.mac) {
    params.set("module_id", moduleMeta.mac);
  }
  // Netatmo enforces both a 10-second rolling window (~50 req/10s/user) and
  // a per-hour quota (~500 req/h/app). One retry on 429 with a 65s pause is
  // usually enough to clear the 10s window; for the per-hour cap, the user
  // can re-run the script (idempotent per equipment+alias).
  const callWithRetry = async (): Promise<Response> => {
    let res = await fetch(
      `${NETATMO_BASE}/api/getmeasure?${params.toString()}`,
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );
    if (res.status === 429) {
      await sleep(65_000);
      res = await fetch(
        `${NETATMO_BASE}/api/getmeasure?${params.toString()}`,
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );
    }
    return res;
  };
  const res = await callWithRetry();
  if (!res.ok) {
    throw new Error(
      `getmeasure ${group.deviceModel} ${day.toISOString().slice(0, 10)}: ${res.status} ${await res.text()}`,
    );
  }
  const data = (await res.json()) as {
    body: Record<string, (number | null)[]>;
  };

  // The hourly bucket has a 90-day retention; trying to write a point
  // older than that triggers an HTTP 422 from InfluxDB
  // ("violates Retention Policy Lower Bound") and the WriteApi flush
  // throws on close. Skip hourly writes for older days; daily-only is
  // still useful (sowel-daily has a 5-year retention).
  const HOURLY_RETENTION_DAYS = 90;
  const hourlyCutoffMs = Date.now() - HOURLY_RETENTION_DAYS * 24 * 3600 * 1000;
  const writeHourly = day.getTime() >= hourlyCutoffMs;

  // Collect raw 30-min points per binding
  // bindings[i] is keyed by alias
  const rawPerBinding = new Map<string, { ts: number; value: number }[]>();
  for (const b of positionToBinding) rawPerBinding.set(b.alias, []);

  const tsKeys = Object.keys(data.body ?? {}).sort();
  for (const tsKey of tsKeys) {
    const tsNum = parseInt(tsKey, 10);
    if (tsNum < dayStartTs || tsNum >= dayEndTs) continue;
    const arr = data.body[tsKey];
    if (!arr) continue;
    for (let i = 0; i < positionToBinding.length; i++) {
      const v = arr[i];
      if (typeof v !== "number" || !Number.isFinite(v)) continue;
      rawPerBinding.get(positionToBinding[i].alias)!.push({ ts: tsNum, value: v });
    }
  }

  // Aggregate per hour + per day, per binding
  let rawCount = 0;
  let hourPointsCount = 0;

  const hourlyWrite = influx.getWriteApi(influxOrg!, hourlyBucket, "s", {
    batchSize: 200,
    flushInterval: 5000,
    maxRetries: 3,
  });
  const dailyWrite = influx.getWriteApi(influxOrg!, dailyBucket, "s", {
    batchSize: 20,
    flushInterval: 5000,
    maxRetries: 3,
  });

  for (const b of positionToBinding) {
    const raws = rawPerBinding.get(b.alias) ?? [];
    if (raws.length === 0) continue;
    rawCount += raws.length;

    // Group by hour (UTC)
    const perHour = new Map<number, number[]>();
    for (const p of raws) {
      const hour = Math.floor(p.ts / 3600) * 3600;
      const arr = perHour.get(hour);
      if (arr) arr.push(p.value);
      else perHour.set(hour, [p.value]);
    }

    // Per-hour writes (skipped for days older than the hourly bucket's
    // 90-day retention — InfluxDB would reject them).
    if (writeHourly) {
      for (const [hourTs, values] of perHour) {
        const points = buildAggPoint({
          bucket: "hourly",
          equipmentId: b.equipmentId,
          zoneId: b.zoneId,
          alias: b.alias,
          category: b.category,
          type: b.type,
          timestampSec: hourTs,
          mean: values.reduce((a, b) => a + b, 0) / values.length,
          min: Math.min(...values),
          max: Math.max(...values),
        });
        for (const p of points) hourlyWrite.writePoint(p);
        hourPointsCount++;
      }
    }

    // Per-day write
    const allValues = raws.map((r) => r.value);
    const dailyPoints = buildAggPoint({
      bucket: "daily",
      equipmentId: b.equipmentId,
      zoneId: b.zoneId,
      alias: b.alias,
      category: b.category,
      type: b.type,
      timestampSec: dayStartTs,
      mean: allValues.reduce((a, b) => a + b, 0) / allValues.length,
      min: Math.min(...allValues),
      max: Math.max(...allValues),
    });
    for (const p of dailyPoints) dailyWrite.writePoint(p);
  }

  // Close both writers independently: if hourly throws (retention bound,
  // network glitch, …), daily can still finish flushing its own buffer.
  const closeResults = await Promise.allSettled([
    hourlyWrite.close(),
    dailyWrite.close(),
  ]);
  const failures = closeResults.filter((r) => r.status === "rejected");
  if (failures.length > 0) {
    throw new Error(
      `${failures.length}/${closeResults.length} writers failed: ${(failures[0] as PromiseRejectedResult).reason}`,
    );
  }

  return { rawPoints: rawCount, hourPoints: hourPointsCount };
}

// ============================================================
// Main
// ============================================================

async function run(): Promise<void> {
  const now = new Date();
  const from = startOfDayUtc(new Date(now));
  from.setUTCMonth(from.getUTCMonth() - MONTHS);
  const to = startOfDayUtc(now);

  const allDays: Date[] = [];
  for (const d of daysBetween(from, to)) allDays.push(d);

  console.log(`\nNetatmo Weather backfill — ${MONTHS} months`);
  console.log(`Range: ${from.toISOString().slice(0, 10)} → ${to.toISOString().slice(0, 10)} (${allDays.length} days)`);
  console.log(`Equipments: ${new Set(bindingRows.map((b) => b.equipmentName)).size}`);
  console.log(`Module groups: ${groups.size}`);
  console.log(`Buckets: hourly=${hourlyBucket}, daily=${dailyBucket}`);

  console.log("\nResolving Netatmo MACs via getstationsdata…");
  const metas = await resolveNetatmoMetas();
  console.log(`Resolved ${metas.size} (name → MAC) entries`);
  for (const g of groups.values()) {
    const m = metas.get(g.sourceDeviceId);
    const b = metas.get(g.baseSourceDeviceId);
    if (!m || !b) {
      console.error(
        `  ✗ Cannot resolve MACs for ${g.equipmentName} / ${g.deviceModel} (module="${g.sourceDeviceId}", base="${g.baseSourceDeviceId}")`,
      );
    } else {
      console.log(
        `  ✓ ${g.equipmentName} / ${g.deviceModel}: device_id=${b.mac.slice(0, 8)}…  module_id=${m.mac.slice(0, 8)}…  (${m.type})`,
      );
    }
  }
  console.log();

  // Idempotency: delete any existing hourly + daily points in the window
  // before we start, scoped to the equipments touched.
  for (const g of groups.values()) {
    const aliasPredicate = g.bindings
      .map((b) => `alias="${b.alias}"`)
      .join(" OR ");
    const predicate = `_measurement="equipment_data" AND equipmentId="${g.equipmentId}" AND (${aliasPredicate})`;
    await deleteRange(hourlyBucket, from, to, predicate);
    await deleteRange(dailyBucket, from, to, predicate);
  }
  console.log("Existing window cleared. Starting fetch...\n");

  let totalRaw = 0;
  let totalHour = 0;
  let processedDays = 0;
  let errors = 0;

  for (const g of groups.values()) {
    console.log(`\n=== ${g.equipmentName} / ${g.deviceModel} ===`);

    for (let i = 0; i < allDays.length; i++) {
      const day = allDays[i];
      const dateStr = day.toISOString().slice(0, 10);
      try {
        const r = await processGroupDay(g, day, metas);
        if (r.rawPoints === 0) {
          process.stdout.write(`  ${dateStr}  ·  no data\n`);
        } else {
          process.stdout.write(
            `  ${dateStr}  ✓  raw=${r.rawPoints}  hourly=${r.hourPoints}\n`,
          );
          totalRaw += r.rawPoints;
          totalHour += r.hourPoints;
          processedDays++;
        }
      } catch (err) {
        errors++;
        console.error(
          `  ${dateStr}  ✗  ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if ((i + 1) % 10 === 0 && i + 1 < allDays.length) {
        process.stdout.write("    … pause 3s (rate limit) …\n");
        await sleep(3000);
      }
    }
  }

  console.log(
    `\nDone. ${processedDays} day-groups processed, ${totalRaw} raw points, ${totalHour} hourly points, ${errors} errors.`,
  );
}

run().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
