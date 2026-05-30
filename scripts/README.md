# Netatmo Weather — Scripts

## `backfill-history.ts`

Backfills historical data from the Netatmo Cloud (`getmeasure` API) into Sowel's InfluxDB downsampled buckets, for every weather equipment bound to this plugin.

Use this when you create a weather equipment in Sowel **after** the modules have been collecting data on the Netatmo side. The plugin only writes points to InfluxDB from the moment Sowel sees a new measurement live, so anything Netatmo had recorded before is normally lost to Sowel's history. This script recovers it.

### How it works

For each equipment of type `weather` whose bindings come from devices registered by the `netatmo_weather` plugin:

1. Reads Sowel's SQLite to discover the `(equipmentId, alias, category, deviceModel, sourceDeviceId)` tuple for every data binding.
2. Loads the plugin's OAuth tokens from `/app/data/netatmo-weather-tokens.json` (the same file the live plugin uses) and refreshes them if needed.
3. For each `(base station, module)` pair on the equipment, calls Netatmo `POST /api/getmeasure` day-by-day at 30-min granularity for the requested number of months.
4. Aggregates the resulting 30-min points into hourly (`mean`/`min`/`max`) and daily (`mean`/`min`/`max`) records, mirroring the schema produced by Sowel's `sowel-downsample-hourly` / `sowel-downsample-daily` Flux tasks.
5. Writes hourly points into the `sowel-hourly` bucket (90-day retention) and daily points into `sowel-daily` (5-year retention). The raw 7-day bucket is intentionally **not** written: anything older than 7 days would be purged immediately by retention.

The script is **idempotent**: the target window is wiped per equipment+alias before each run, so re-running it is safe.

### Usage

The script runs **inside the Sowel container** (it uses Sowel's `node_modules` for `better-sqlite3` + `@influxdata/influxdb-client`):

```bash
docker exec sowel npx tsx \
  /app/plugins/installed/netatmo_weather/scripts/backfill-history.ts \
  [months]
```

- `months` defaults to **12**. Hard cap **60** (matches the `sowel-daily` retention).
- Rate-limit pause of 3 s every 10 days to stay well under Netatmo's ~50 req / 10 s limit.

### Prerequisites

- The Netatmo Weather plugin is configured (client_id, client_secret, refresh_token in the Admin UI) and has at least one successful start (so `data/netatmo-weather-tokens.json` exists with a fresh `refreshToken`).
- A weather equipment exists in Sowel with bindings to the relevant modules (outdoor, wind, rain, indoor, …). Bindings can be created either by the auto-bind flow at equipment creation or manually.
- The Sowel container has network access to `api.netatmo.com` and to its own InfluxDB.

### Output

For each `(equipment, module, day)` the script prints either:

- `2026-04-15  ✓  raw=48  hourly=24` — full day collected (typically 48 raw 30-min points and 24 hourly aggregates)
- `2026-04-15  ·  no data` — Netatmo had nothing for that module on that day (sensor not yet installed, offline, etc.)
- `2026-04-15  ✗  <error>` — call failed; processing continues with the next day

The final line summarises totals: processed day-groups, raw points consumed, hourly points written, errors.

### Tuning

- `SOWEL_DB_PATH` env var — override the SQLite path (default `/app/data/sowel.db`).
- `NETATMO_WEATHER_TOKENS_PATH` env var — override the tokens file path (default `/app/data/netatmo-weather-tokens.json`).
