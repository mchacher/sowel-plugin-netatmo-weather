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

const influxUrl = getSetting("history.influx.url");
const influxToken = getSetting("history.influx.token");
const influxOrg = getSetting("history.influx.org");
const influxBucket = getSetting("history.influx.bucket");
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

/** Maps the device-data `key` (or alias-stripped) to the Netatmo API `type`. */
const KEY_TO_NETATMO_TYPE: Record<string, string> = {
  temperature: "Temperature",
  humidity: "Humidity",
  pressure: "Pressure",
  co2: "CO2",
  noise: "Noise",
  rain: "Rain",
  sum_rain_1: "sum_rain_1",
  sum_rain_24: "sum_rain_24",
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
): Promise<DayResult> {
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
    const netatmoType = KEY_TO_NETATMO_TYPE[key] ?? KEY_TO_NETATMO_TYPE[b.deviceKey];
    if (!netatmoType) continue;
    apiTypes.push(netatmoType);
    positionToBinding.push(b);
  }
  if (apiTypes.length === 0) return { rawPoints: 0, hourPoints: 0 };

  const accessToken = await getAccessToken();
  const params = new URLSearchParams({
    device_id: group.baseSourceDeviceId,
    type: apiTypes.join(","),
    scale: "30min",
    optimize: "false",
    real_time: "true",
    date_begin: String(dayStartTs),
    date_end: String(dayEndTs),
  });
  // Only set module_id when the binding is on a module, not the base
  if (group.sourceDeviceId !== group.baseSourceDeviceId) {
    params.set("module_id", group.sourceDeviceId);
  }
  const res = await fetch(
    `${NETATMO_BASE}/api/getmeasure?${params.toString()}`,
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  if (!res.ok) {
    throw new Error(
      `getmeasure ${group.deviceModel} ${day.toISOString().slice(0, 10)}: ${res.status} ${await res.text()}`,
    );
  }
  const data = (await res.json()) as {
    body: Record<string, (number | null)[]>;
  };

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

    // Per-hour writes
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

  await hourlyWrite.close();
  await dailyWrite.close();

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
  console.log(`Buckets: hourly=${hourlyBucket}, daily=${dailyBucket}\n`);

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
        const r = await processGroupDay(g, day);
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
