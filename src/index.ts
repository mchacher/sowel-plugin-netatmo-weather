/**
 * Sowel Plugin: Netatmo Weather
 *
 * Polls Netatmo Weather Station data via the getstationsdata API.
 * Discovers base station + outdoor/wind/rain/indoor modules.
 * Read-only — no orders.
 *
 * Rain follows Sowel's per-hour contract: `rain` is the total of one clock
 * hour, sent with `sourceTimestamp` = the hour start. The totals come from
 * Netatmo's own hourly aggregate (getmeasure, sum_rain), never from the
 * dashboard's `Rain`, which is the latest 5-minute measure and cannot be
 * summed (the dashboard refreshes every ~10 minutes, so a poll every 5 reads
 * some measures twice and misses others). A year of hours is backfilled, 1000
 * hours per poll (nine polls).
 *
 * Netatmo's `sum_rain_24` is the rain since local midnight despite its name
 * (it drops to 0 at midnight). In Sowel `sum_rain_24` is the rolling 24 hours
 * and the since-midnight figure is `rain_today` (sowel#1037): Netatmo's value
 * is published as `rain_today`, and `sum_rain_24` is the sum of the last 24
 * hourly totals.
 *
 * Uses OAuth 2.0 with automatic token refresh and file persistence.
 */

import * as fs from "node:fs";
import * as path from "node:path";

// ============================================================
// Local type definitions (no imports from Sowel source)
// ============================================================

interface Logger {
  child(bindings: Record<string, unknown>): Logger;
  info(obj: Record<string, unknown>, msg: string): void;
  info(msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  warn(msg: string): void;
  error(obj: Record<string, unknown>, msg: string): void;
  error(msg: string): void;
  debug(obj: Record<string, unknown>, msg: string): void;
  debug(msg: string): void;
}

interface EventBus {
  emit(event: unknown): void;
}

interface SettingsManager {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
}

interface DiscoveredDevice {
  friendlyName: string;
  manufacturer?: string;
  model?: string;
  data: {
    key: string;
    type: string;
    category: string;
    unit?: string;
  }[];
  orders: {
    key: string;
    type: string;
    dispatchConfig?: Record<string, unknown>;
    min?: number;
    max?: number;
    enumValues?: string[];
    unit?: string;
  }[];
}

interface DeviceManager {
  upsertFromDiscovery(
    integrationId: string,
    source: string,
    discovered: DiscoveredDevice,
  ): void;
  updateDeviceData(
    integrationId: string,
    sourceDeviceId: string,
    payload: Record<string, unknown>,
    sourceTimestamp?: number,
  ): void;
  migrateIntegrationId(
    oldIntegrationId: string,
    newIntegrationId: string,
    models?: string[],
  ): number;
}

interface Device {
  id: string;
  integrationId: string;
  sourceDeviceId: string;
  name: string;
}

interface PluginDeps {
  logger: Logger;
  eventBus: EventBus;
  settingsManager: SettingsManager;
  deviceManager: DeviceManager;
  pluginDir: string;
}

type IntegrationStatus = "connected" | "disconnected" | "not_configured" | "error";

interface IntegrationSettingDef {
  key: string;
  label: string;
  type: "text" | "password" | "number" | "boolean";
  required: boolean;
  placeholder?: string;
  defaultValue?: string;
}

interface IntegrationPlugin {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly icon: string;
  readonly apiVersion?: number;
  getStatus(): IntegrationStatus;
  isConfigured(): boolean;
  getSettingsSchema(): IntegrationSettingDef[];
  start(options?: { pollOffset?: number }): Promise<void>;
  stop(): Promise<void>;
  executeOrder(
    device: Device,
    orderKeyOrDispatchConfig: string | Record<string, unknown>,
    value: unknown,
  ): Promise<void>;
  refresh?(): Promise<void>;
  getPollingInfo?(): { lastPollAt: string; intervalMs: number } | null;
}

// ============================================================
// Netatmo API types
// ============================================================

interface NetatmoTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

interface NetatmoStationsDataResponse {
  body: {
    devices: NetatmoStationDevice[];
  };
  status: string;
}

interface NetatmoStationDevice {
  _id: string;
  type: string; // "NAMain"
  station_name: string;
  module_name: string;
  firmware: number;
  wifi_status: number;
  dashboard_data: NetatmoDashboard;
  modules?: NetatmoStationModule[];
}

interface NetatmoStationModule {
  _id: string;
  type: string; // "NAModule1" | "NAModule2" | "NAModule3" | "NAModule4"
  module_name: string;
  firmware: number;
  rf_status: number;
  battery_percent: number;
  dashboard_data?: NetatmoDashboard;
}

interface NetatmoDashboard {
  Temperature?: number;
  Humidity?: number;
  CO2?: number;
  Noise?: number;
  Pressure?: number;
  AbsolutePressure?: number;
  min_temp?: number;
  max_temp?: number;
  WindStrength?: number;
  WindAngle?: number;
  GustStrength?: number;
  GustAngle?: number;
  Rain?: number;
  sum_rain_1?: number;
  sum_rain_24?: number;
  time_utc?: number;
}

/** getmeasure with optimize=false: `{ "<epoch s>": [value] }`. */
interface NetatmoMeasureResponse {
  body: Record<string, Array<number | null>>;
  status: string;
}

// ============================================================
// Constants
// ============================================================

const INTEGRATION_ID = "netatmo_weather";
const LEGACY_INTEGRATION_ID = "netatmo_hc";
const SETTINGS_PREFIX = `integration.${INTEGRATION_ID}.`;
const BASE_URL = "https://api.netatmo.com";
const REQUEST_TIMEOUT_MS = 30_000;
const REFRESH_MARGIN_S = 300;
const DEFAULT_POLL_INTERVAL_MS = 300_000;
/** Consecutive poll failures before raising a system alarm (~30 min at the 5-min cadence). */
const POLL_FAILURE_ALARM_THRESHOLD = 6;
const POLL_ALARM_ID = "netatmo-weather-poll";
/**
 * Hours re-read on every poll, before the current one: they cover the rolling
 * 24 hours (`sum_rain_24`), late uploads from Netatmo and a failed poll.
 */
const RAIN_RECENT_HOURS = 23;
/** How far back the backfill reaches, inside Sowel's one-year rain retention. */
const RAIN_BACKFILL_DAYS = 364;
/**
 * Hours backfilled per poll: getmeasure returns at most 1024 values, so a year
 * takes nine polls (~45 min at the default 5 min), newest weeks first.
 */
const RAIN_BACKFILL_STEP_HOURS = 1000;
/** Consecutive failures of one backfill step before it is skipped, so it cannot stall forever. */
const RAIN_BACKFILL_MAX_FAILURES = 3;
/** How far back the recent read catches up after an outage (getmeasure returns at most 1024 values). */
const RAIN_CATCH_UP_HOURS = 1000;

const WEATHER_MODEL_NAMES: Record<string, string> = {
  NAMain: "Indoor Station",
  NAModule1: "Outdoor Module",
  NAModule2: "Wind Gauge",
  NAModule3: "Rain Gauge",
  NAModule4: "Indoor Module",
};

// ============================================================
// Poll failure tracking (issue #2)
// ============================================================

/**
 * Counts consecutive poll failures and decides when the system alarm
 * should be raised (threshold reached) or resolved (first success after
 * a raise). Pure state machine, exported for tests.
 */
export class PollFailureTracker {
  private failures = 0;
  private raised = false;

  constructor(private readonly threshold: number) {}

  get consecutiveFailures(): number {
    return this.failures;
  }

  recordFailure(): "raise" | null {
    this.failures += 1;
    if (!this.raised && this.failures >= this.threshold) {
      this.raised = true;
      return "raise";
    }
    return null;
  }

  recordSuccess(): "resolve" | null {
    this.failures = 0;
    if (this.raised) {
      this.raised = false;
      return "resolve";
    }
    return null;
  }
}

// ============================================================
// Hourly rain (Sowel per-hour contract)
// ============================================================

export interface RainHour {
  /** Start of the clock hour, epoch seconds. */
  hourStart: number;
  mm: number;
}

const floorHour = (s: number) => Math.floor(s / 3600) * 3600;

/**
 * Hourly rain totals from a getmeasure body, oldest first. Netatmo stamps an
 * aggregate at its middle (start + scale/2) unless `real_time` is set, so the
 * stamp is floored to the hour either way. Hours without a value are skipped.
 */
export function parseRainHours(body: unknown): RainHour[] {
  if (!body || typeof body !== "object" || Array.isArray(body)) return [];
  const hours: RainHour[] = [];
  for (const [ts, values] of Object.entries(body as Record<string, unknown>)) {
    const t = Number(ts);
    const mm = Array.isArray(values) ? values[0] : undefined;
    if (!Number.isFinite(t) || typeof mm !== "number" || !Number.isFinite(mm)) continue;
    hours.push({ hourStart: floorHour(t), mm });
  }
  return hours.sort((a, b) => a.hourStart - b.hourStart);
}

/**
 * Next backfill step: the {@link RAIN_BACKFILL_STEP_HOURS} hours just before `backfilledTo` (the oldest
 * hour already backfilled, epoch s), or before the recent hours on the first
 * step. Null once the backfill has reached {@link RAIN_BACKFILL_DAYS}. `end`
 * reaches half an hour into the previous step, so the boundary hour is read
 * twice whatever way Netatmo bounds `date_end`: sending an hour again is
 * harmless, a hole is not.
 */
export function nextBackfillWindow(
  nowS: number,
  backfilledTo: number | null,
): { begin: number; end: number } | null {
  const current = floorHour(nowS);
  const from = backfilledTo ?? current - RAIN_RECENT_HOURS * 3600;
  const limit = current - RAIN_BACKFILL_DAYS * 86_400;
  if (from <= limit) return null;
  return { begin: Math.max(from - RAIN_BACKFILL_STEP_HOURS * 3600, limit), end: from + 1800 };
}

/**
 * Rain over the rolling 24 hours, to the hour: the current hour so far plus
 * the {@link RAIN_RECENT_HOURS} before it. Hours without a total had no rain.
 */
export function rolling24h(hours: RainHour[], nowS: number): number {
  const first = floorHour(nowS) - RAIN_RECENT_HOURS * 3600;
  const sum = hours.filter((h) => h.hourStart >= first).reduce((acc, h) => acc + h.mm, 0);
  return Math.round(sum * 1000) / 1000;
}

/**
 * Where the recent read starts: the last {@link RAIN_RECENT_HOURS}, or further
 * back to the newest hour already read (`syncedTo`) after an outage, within
 * {@link RAIN_CATCH_UP_HOURS}.
 */
export function recentReadStart(nowS: number, syncedTo: number | null): number {
  const current = floorHour(nowS);
  const recent = current - RAIN_RECENT_HOURS * 3600;
  if (syncedTo === null || syncedTo >= recent) return recent;
  return Math.max(syncedTo, current - RAIN_CATCH_UP_HOURS * 3600);
}

// ============================================================
// OAuth Bridge (self-contained)
// ============================================================

export class NetatmoBridge {
  private logger: Logger;
  private clientId: string;
  private clientSecret: string;
  private accessToken: string | null = null;
  private refreshToken: string;
  private tokenExpiresAt = 0;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private tokenFilePath: string;
  private onRefreshTokenUpdated: ((newToken: string) => void) | null = null;

  constructor(
    clientId: string,
    clientSecret: string,
    refreshToken: string,
    logger: Logger,
    tokenFilePath: string,
    onRefreshTokenUpdated?: (newToken: string) => void,
  ) {
    this.logger = logger;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.refreshToken = refreshToken;
    this.tokenFilePath = tokenFilePath;
    this.onRefreshTokenUpdated = onRefreshTokenUpdated ?? null;
    this.loadTokensFromFile();
  }

  async authenticate(): Promise<void> {
    await this.doRefreshToken();
    this.scheduleRefresh();
  }

  disconnect(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.accessToken = null;
  }

  async getStationsData(): Promise<NetatmoStationsDataResponse> {
    return this.apiGet<NetatmoStationsDataResponse>("/api/getstationsdata");
  }

  /** Netatmo's hourly rain totals for a rain module, from `beginS` (to `endS`, else now). */
  async getRainHours(
    stationId: string,
    moduleId: string,
    beginS: number,
    endS?: number,
  ): Promise<RainHour[]> {
    const query = new URLSearchParams({
      device_id: stationId,
      module_id: moduleId,
      scale: "1hour",
      type: "sum_rain",
      date_begin: String(beginS),
      optimize: "false",
    });
    if (endS !== undefined) query.set("date_end", String(endS));
    const res = await this.apiGet<NetatmoMeasureResponse>(`/api/getmeasure?${query.toString()}`);
    return parseRainHours(res.body);
  }

  private async doRefreshToken(): Promise<void> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: this.refreshToken,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    const res = await this.rawFetch(`${BASE_URL}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token refresh failed (${res.status}): ${text}`);
    }

    const data = (await res.json()) as NetatmoTokenResponse;
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

    this.saveTokensToFile();

    if (this.onRefreshTokenUpdated) {
      this.onRefreshTokenUpdated(data.refresh_token);
    }

    this.logger.info({ expiresIn: data.expires_in }, "Access token refreshed");
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);

    const msUntilExpiry = this.tokenExpiresAt - Date.now();
    const msUntilRefresh = Math.max(msUntilExpiry - REFRESH_MARGIN_S * 1000, 60_000);

    this.refreshTimer = setTimeout(async () => {
      try {
        await this.doRefreshToken();
        this.scheduleRefresh();
      } catch (err) {
        this.logger.warn({ err } as Record<string, unknown>, "Token refresh failed, retrying in 30s");
        this.refreshTimer = setTimeout(async () => {
          try {
            await this.doRefreshToken();
            this.scheduleRefresh();
          } catch (retryErr) {
            this.logger.error(
              { err: retryErr } as Record<string, unknown>,
              "Token refresh retry failed",
            );
          }
        }, 30_000);
      }
    }, msUntilRefresh);
  }

  private loadTokensFromFile(): void {
    try {
      if (fs.existsSync(this.tokenFilePath)) {
        const raw = fs.readFileSync(this.tokenFilePath, "utf-8");
        const saved = JSON.parse(raw) as {
          refreshToken?: string;
          accessToken?: string;
          expiresAt?: number;
        };
        if (saved.refreshToken) {
          this.refreshToken = saved.refreshToken;
        }
        if (saved.accessToken && saved.expiresAt && saved.expiresAt > Date.now()) {
          this.accessToken = saved.accessToken;
          this.tokenExpiresAt = saved.expiresAt;
        }
      }
    } catch {
      // No saved tokens, will use configured refresh_token
    }
  }

  private saveTokensToFile(): void {
    try {
      const dir = path.dirname(this.tokenFilePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        this.tokenFilePath,
        JSON.stringify({
          refreshToken: this.refreshToken,
          accessToken: this.accessToken,
          expiresAt: this.tokenExpiresAt,
        }),
      );
    } catch (err) {
      this.logger.error({ err } as Record<string, unknown>, "Failed to persist tokens");
    }
  }

  private async apiGet<T>(endpoint: string): Promise<T> {
    // Auto-refresh if token is expired or about to expire
    if (this.accessToken && this.tokenExpiresAt > 0 && Date.now() > this.tokenExpiresAt - 60_000) {
      await this.doRefreshToken();
    }

    let res = await this.authorizedGet(endpoint);

    if (res.status === 401 || res.status === 403) {
      // A token we believe fresh got refused: revoked grant, or a
      // refresh-token rotation race with another consumer of the same
      // grant. Re-refresh once and retry immediately instead of failing
      // every poll until the next scheduled refresh (issue #2).
      this.logger.warn(
        { endpoint, status: res.status },
        "Access token refused — forcing token re-refresh",
      );
      await this.doRefreshToken();
      res = await this.authorizedGet(endpoint);
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`API ${endpoint} failed (${res.status}): ${text}`);
    }

    return (await res.json()) as T;
  }

  private async authorizedGet(endpoint: string): Promise<Response> {
    return this.rawFetch(`${BASE_URL}${endpoint}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });
  }

  private async rawFetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }
}

// ============================================================
// Weather data mapping
// ============================================================

function mapStationToDiscovered(device: NetatmoStationDevice): DiscoveredDevice {
  return {
    friendlyName: device.module_name || device.station_name,
    manufacturer: "Netatmo",
    model: WEATHER_MODEL_NAMES[device.type] ?? device.type,
    data: [
      { key: "temperature", type: "number", category: "temperature", unit: "°C" },
      { key: "humidity", type: "number", category: "humidity", unit: "%" },
      { key: "co2", type: "number", category: "co2", unit: "ppm" },
      { key: "noise", type: "number", category: "noise", unit: "dB" },
      { key: "pressure", type: "number", category: "pressure", unit: "mbar" },
    ],
    orders: [],
  };
}

function mapModuleToDiscovered(mod: NetatmoStationModule): DiscoveredDevice {
  const data: DiscoveredDevice["data"] = [];
  data.push({ key: "battery", type: "number", category: "battery", unit: "%" });

  switch (mod.type) {
    case "NAModule1":
      data.push({ key: "temperature", type: "number", category: "temperature_outdoor", unit: "°C" });
      data.push({ key: "humidity", type: "number", category: "humidity_outdoor", unit: "%" });
      break;
    case "NAModule2":
      data.push({ key: "wind_strength", type: "number", category: "wind", unit: "km/h" });
      data.push({ key: "wind_angle", type: "number", category: "wind", unit: "°" });
      data.push({ key: "gust_strength", type: "number", category: "wind", unit: "km/h" });
      data.push({ key: "gust_angle", type: "number", category: "wind", unit: "°" });
      break;
    case "NAModule3":
      data.push({ key: "rain", type: "number", category: "rain", unit: "mm" });
      data.push({ key: "sum_rain_1", type: "number", category: "rain", unit: "mm" });
      data.push({ key: "sum_rain_24", type: "number", category: "rain", unit: "mm" });
      data.push({ key: "rain_today", type: "number", category: "rain", unit: "mm" });
      break;
    case "NAModule4":
      data.push({ key: "temperature", type: "number", category: "temperature", unit: "°C" });
      data.push({ key: "humidity", type: "number", category: "humidity", unit: "%" });
      data.push({ key: "co2", type: "number", category: "co2", unit: "ppm" });
      break;
  }

  return {
    friendlyName: mod.module_name || mod._id,
    manufacturer: "Netatmo",
    model: WEATHER_MODEL_NAMES[mod.type] ?? mod.type,
    data,
    orders: [],
  };
}

function extractDashboardPayload(
  dashboard: NetatmoDashboard,
  moduleType: string,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {};

  switch (moduleType) {
    case "NAMain":
      if (dashboard.Temperature !== undefined) payload.temperature = dashboard.Temperature;
      if (dashboard.Humidity !== undefined) payload.humidity = dashboard.Humidity;
      if (dashboard.CO2 !== undefined) payload.co2 = dashboard.CO2;
      if (dashboard.Noise !== undefined) payload.noise = dashboard.Noise;
      if (dashboard.Pressure !== undefined) payload.pressure = dashboard.Pressure;
      break;
    case "NAModule1":
      if (dashboard.Temperature !== undefined) payload.temperature = dashboard.Temperature;
      if (dashboard.Humidity !== undefined) payload.humidity = dashboard.Humidity;
      break;
    case "NAModule2":
      if (dashboard.WindStrength !== undefined) payload.wind_strength = dashboard.WindStrength;
      if (dashboard.WindAngle !== undefined) payload.wind_angle = dashboard.WindAngle;
      if (dashboard.GustStrength !== undefined) payload.gust_strength = dashboard.GustStrength;
      if (dashboard.GustAngle !== undefined) payload.gust_angle = dashboard.GustAngle;
      break;
    case "NAModule3":
      // `rain` is published per hour from getmeasure (see syncRainHours), not
      // from the dashboard's 5-minute `Rain`.
      if (dashboard.sum_rain_1 !== undefined) payload.sum_rain_1 = dashboard.sum_rain_1;
      // Netatmo's sum_rain_24 is the rain since midnight: Sowel's rain_today.
      // sum_rain_24, the rolling 24 hours, is summed from the hourly totals.
      if (dashboard.sum_rain_24 !== undefined) payload.rain_today = dashboard.sum_rain_24;
      break;
    case "NAModule4":
      if (dashboard.Temperature !== undefined) payload.temperature = dashboard.Temperature;
      if (dashboard.Humidity !== undefined) payload.humidity = dashboard.Humidity;
      if (dashboard.CO2 !== undefined) payload.co2 = dashboard.CO2;
      break;
  }

  return payload;
}

// ============================================================
// Plugin implementation
// ============================================================

class NetatmoWeatherPlugin implements IntegrationPlugin {
  readonly id = INTEGRATION_ID;
  readonly name = "Netatmo Weather";
  readonly description = "Netatmo Weather Station — temperature, humidity, pressure, CO2, wind, rain";
  readonly icon = "CloudSun";
  readonly apiVersion = 2;

  private logger: Logger;
  private eventBus: EventBus;
  private settingsManager: SettingsManager;
  private deviceManager: DeviceManager;
  private bridge: NetatmoBridge | null = null;
  private status: IntegrationStatus = "disconnected";
  private pollInterval: ReturnType<typeof setInterval> | null = null;
  private lastPollAt: string | null = null;
  private failureTracker = new PollFailureTracker(POLL_FAILURE_ALARM_THRESHOLD);
  private pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
  private retryTimeout: ReturnType<typeof setTimeout> | null = null;
  private retryCount = 0;
  private migrationDone = false;
  private dataDir: string;
  /** Rain hours last published, per module, so a poll only resends what changed. */
  private publishedRain = new Map<string, Map<number, number>>();
  /** Hours sent while still open, per module: each is sent once more after it closes. */
  private openRainHours = new Map<string, Set<number>>();
  /** Consecutive failures of the pending backfill step, per module. */
  private backfillFailures = new Map<string, number>();

  constructor(deps: PluginDeps) {
    this.logger = deps.logger;
    this.eventBus = deps.eventBus;
    this.settingsManager = deps.settingsManager;
    this.deviceManager = deps.deviceManager;
    // data/ is one level up from plugins/<id>/
    this.dataDir = path.resolve(deps.pluginDir, "..", "..", "data");
  }

  getStatus(): IntegrationStatus {
    if (!this.isConfigured()) return "not_configured";
    return this.status;
  }

  isConfigured(): boolean {
    return (
      this.getSetting("client_id") !== undefined &&
      this.getSetting("client_secret") !== undefined &&
      this.getSetting("refresh_token") !== undefined
    );
  }

  getSettingsSchema(): IntegrationSettingDef[] {
    return [
      { key: "client_id", label: "Client ID", type: "text", required: true, placeholder: "From dev.netatmo.com" },
      { key: "client_secret", label: "Client Secret", type: "password", required: true },
      { key: "refresh_token", label: "Refresh Token", type: "password", required: true, placeholder: "With read_station scope" },
      { key: "polling_interval", label: "Polling interval (seconds)", type: "number", required: false, defaultValue: "300", placeholder: "Min 60, default 300" },
    ];
  }

  async start(options?: { pollOffset?: number }): Promise<void> {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    if (this.bridge) {
      this.bridge.disconnect();
      this.bridge = null;
    }

    if (!this.isConfigured()) {
      this.status = "not_configured";
      return;
    }

    const clientId = this.getSetting("client_id")!;
    const clientSecret = this.getSetting("client_secret")!;
    const refreshToken = this.getSetting("refresh_token")!;
    const pollingIntervalSec = parseInt(this.getSetting("polling_interval") ?? "300", 10);
    this.pollIntervalMs = (isNaN(pollingIntervalSec) ? 300 : Math.max(pollingIntervalSec, 60)) * 1000;

    const tokenFilePath = path.join(this.dataDir, "netatmo-weather-tokens.json");

    // Migrate devices from legacy netatmo_hc BEFORE authentication (DB-only, no API needed)
    if (!this.migrationDone) {
      this.migrateFromLegacy();
      this.migrationDone = true;
    }

    try {
      this.bridge = new NetatmoBridge(
        clientId,
        clientSecret,
        refreshToken,
        this.logger,
        tokenFilePath,
        (newToken) => {
          this.settingsManager.set(`${SETTINGS_PREFIX}refresh_token`, newToken);
        },
      );

      await this.bridge.authenticate();

      // First poll
      await this.poll();

      // Schedule periodic polling
      const offset = options?.pollOffset ?? 0;
      if (offset > 0) {
        setTimeout(() => {
          this.pollInterval = setInterval(() => this.safePoll(), this.pollIntervalMs);
        }, offset);
      } else {
        this.pollInterval = setInterval(() => this.safePoll(), this.pollIntervalMs);
      }

      this.status = "connected";
      this.retryCount = 0;
      this.eventBus.emit({ type: "system.integration.connected", integrationId: this.id });
      this.logger.info({ pollIntervalMs: this.pollIntervalMs }, "Netatmo Weather started");
    } catch (err) {
      this.status = "error";
      this.logger.error({ err } as Record<string, unknown>, "Failed to start Netatmo Weather");
      this.scheduleRetry();
    }
  }

  async stop(): Promise<void> {
    this.cancelRetry();
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    if (this.bridge) {
      this.bridge.disconnect();
      this.bridge = null;
    }
    this.status = "disconnected";
    this.eventBus.emit({ type: "system.integration.disconnected", integrationId: this.id });
    this.logger.info("Netatmo Weather stopped");
  }

  async executeOrder(
    _device: Device,
    _orderKey: string,
    _value: unknown,
  ): Promise<void> {
    throw new Error("Netatmo Weather is read-only — no orders supported");
  }

  async refresh(): Promise<void> {
    if (!this.bridge || this.status !== "connected") {
      throw new Error("Netatmo Weather not connected");
    }
    await this.poll();
    this.logger.info("Manual refresh completed");
  }

  getPollingInfo(): { lastPollAt: string; intervalMs: number } | null {
    if (!this.lastPollAt) return null;
    return { lastPollAt: this.lastPollAt, intervalMs: this.pollIntervalMs };
  }

  // ============================================================
  // Polling
  // ============================================================

  private async poll(): Promise<void> {
    if (!this.bridge) return;

    const stationsData = await this.bridge.getStationsData();
    const devices = stationsData.body.devices;

    if (devices.length === 0) {
      this.logger.debug({}, "No weather stations found");
      return;
    }

    for (const station of devices) {
      // Discover + update base station
      const baseName = station.module_name || station.station_name;
      const baseDiscovered = mapStationToDiscovered(station);
      this.deviceManager.upsertFromDiscovery(INTEGRATION_ID, INTEGRATION_ID, baseDiscovered);

      const basePayload = extractDashboardPayload(station.dashboard_data, station.type);
      this.deviceManager.updateDeviceData(INTEGRATION_ID, baseName, basePayload);

      // Discover + update each sub-module
      for (const mod of station.modules ?? []) {
        const modName = mod.module_name || mod._id;
        const modDiscovered = mapModuleToDiscovered(mod);
        this.deviceManager.upsertFromDiscovery(INTEGRATION_ID, INTEGRATION_ID, modDiscovered);

        const modPayload: Record<string, unknown> = mod.dashboard_data
          ? extractDashboardPayload(mod.dashboard_data, mod.type)
          : {};
        if (mod.battery_percent !== undefined) {
          modPayload.battery = mod.battery_percent;
        }
        this.deviceManager.updateDeviceData(INTEGRATION_ID, modName, modPayload);

        if (mod.type === "NAModule3") {
          await this.syncRainHours(station._id, mod._id, modName);
        }
      }
    }

    this.lastPollAt = new Date().toISOString();
    this.logger.info({ stationCount: devices.length }, "Weather poll complete");

    if (this.failureTracker.recordSuccess() === "resolve") {
      this.eventBus.emit({
        type: "system.alarm.resolved",
        alarmId: POLL_ALARM_ID,
        source: INTEGRATION_ID,
        message: "Netatmo Weather polling recovered",
      });
    }
  }

  /**
   * Publish Netatmo's hourly rain totals: one backfill step, then the recent
   * hours, each with `sourceTimestamp` = its hour start. Sowel writes an hour
   * that is already over straight to its hourly history, so a late or
   * corrected hour, and the backfill, land where they belong. The recent read
   * also gives the rolling 24 hours (`sum_rain_24`). The two reads fail apart,
   * and neither fails the poll: the other readings are still good.
   */
  private async syncRainHours(stationId: string, moduleId: string, modName: string): Promise<void> {
    if (!this.bridge) return;
    const nowS = Math.floor(Date.now() / 1000);
    await this.backfillRainStep(stationId, moduleId, modName, nowS);

    const syncedKey = `rain_synced_to.${moduleId}`;
    const synced = Number(this.getSetting(syncedKey));
    try {
      const recent = await this.bridge.getRainHours(
        stationId,
        moduleId,
        recentReadStart(nowS, Number.isFinite(synced) && synced > 0 ? synced : null),
      );
      this.publishRecentRainHours(moduleId, modName, recent, nowS);
      this.deviceManager.updateDeviceData(INTEGRATION_ID, modName, {
        sum_rain_24: rolling24h(recent, nowS),
      });
      const newest = recent[recent.length - 1];
      if (newest) this.settingsManager.set(`${SETTINGS_PREFIX}${syncedKey}`, String(newest.hourStart));
    } catch (err) {
      this.logger.warn({ err, moduleId } as Record<string, unknown>, "Hourly rain fetch failed");
    }
  }

  /** One backfill step, skipped after repeated failures so it can never stall. */
  private async backfillRainStep(
    stationId: string,
    moduleId: string,
    modName: string,
    nowS: number,
  ): Promise<void> {
    if (!this.bridge) return;
    const key = `rain_backfill.${moduleId}`;
    const saved = Number(this.getSetting(key));
    const window = nextBackfillWindow(nowS, Number.isFinite(saved) && saved > 0 ? saved : null);
    if (!window) return;
    try {
      const hours = await this.bridge.getRainHours(stationId, moduleId, window.begin, window.end);
      for (const h of hours) {
        this.deviceManager.updateDeviceData(INTEGRATION_ID, modName, { rain: h.mm }, h.hourStart);
      }
      this.backfillFailures.delete(moduleId);
      this.settingsManager.set(`${SETTINGS_PREFIX}${key}`, String(window.begin));
      this.logger.info(
        { moduleId, hours: hours.length, from: new Date(window.begin * 1000).toISOString() },
        "Rain history backfill step",
      );
    } catch (err) {
      const failures = (this.backfillFailures.get(moduleId) ?? 0) + 1;
      if (failures < RAIN_BACKFILL_MAX_FAILURES) {
        this.backfillFailures.set(moduleId, failures);
        this.logger.warn({ err, moduleId, failures } as Record<string, unknown>, "Rain backfill step failed");
        return;
      }
      this.backfillFailures.delete(moduleId);
      this.settingsManager.set(`${SETTINGS_PREFIX}${key}`, String(window.begin));
      this.logger.warn(
        { err, moduleId, from: new Date(window.begin * 1000).toISOString() } as Record<string, unknown>,
        "Rain backfill step skipped after repeated failures",
      );
    }
  }

  /**
   * Send the recent hours oldest first, each only if its total changed, with
   * two exceptions. An hour sent while it was still open is sent once more
   * after it closes: Sowel then writes its final total to the hourly history,
   * over whatever the downsample made of it (old 5-minute samples on the
   * upgrade hour, or a last push flushed after the downsample ran). And the
   * newest hour is always sent last, so the live `rain` is the latest hour.
   */
  private publishRecentRainHours(
    moduleId: string,
    modName: string,
    hours: RainHour[],
    nowS: number,
  ): void {
    const current = floorHour(nowS);
    const sent = this.publishedRain.get(moduleId) ?? new Map<number, number>();
    const open = this.openRainHours.get(moduleId) ?? new Set<number>();
    hours.forEach((h, i) => {
      const newest = i === hours.length - 1;
      const closedSinceSent = h.hourStart < current && open.has(h.hourStart);
      if (!newest && !closedSinceSent && sent.get(h.hourStart) === h.mm) return;
      this.deviceManager.updateDeviceData(INTEGRATION_ID, modName, { rain: h.mm }, h.hourStart);
      sent.set(h.hourStart, h.mm);
      if (h.hourStart >= current) open.add(h.hourStart);
      else open.delete(h.hourStart);
    });
    const cutoff = current - (RAIN_RECENT_HOURS + 1) * 3600;
    for (const hourStart of sent.keys()) if (hourStart < cutoff) sent.delete(hourStart);
    for (const hourStart of open) if (hourStart < cutoff) open.delete(hourStart);
    this.publishedRain.set(moduleId, sent);
    this.openRainHours.set(moduleId, open);
  }

  private safePoll(): void {
    this.poll().catch((err) => {
      this.logger.warn({ err } as Record<string, unknown>, "Weather poll failed");
      if (this.failureTracker.recordFailure() === "raise") {
        const msg = err instanceof Error ? err.message : String(err);
        this.eventBus.emit({
          type: "system.alarm.raised",
          alarmId: POLL_ALARM_ID,
          level: "error",
          source: INTEGRATION_ID,
          message: `Netatmo Weather polling failing (${this.failureTracker.consecutiveFailures} consecutive errors) — last error: ${msg}`,
        });
      }
    });
  }

  // ============================================================
  // Legacy migration (netatmo_hc → netatmo_weather)
  // ============================================================

  private migrateFromLegacy(): void {
    try {
      // Migrate weather devices by model name (DB-only, no API call needed).
      // Safe to call before bridge authentication.
      const WEATHER_MODELS = ["Indoor Station", "Outdoor Module", "Wind Gauge", "Rain Gauge", "Indoor Module"];
      const migrated = this.deviceManager.migrateIntegrationId(
        LEGACY_INTEGRATION_ID,
        INTEGRATION_ID,
        WEATHER_MODELS,
      );

      if (migrated > 0) {
        this.logger.info(
          { migrated },
          "Migrated weather devices from netatmo_hc to netatmo_weather",
        );
      }
    } catch (err) {
      this.logger.warn({ err } as Record<string, unknown>, "Legacy migration failed (non-fatal)");
    }
  }

  // ============================================================
  // Retry
  // ============================================================

  private scheduleRetry(): void {
    this.cancelRetry();
    this.retryCount++;
    const delaySec = Math.min(30 * Math.pow(2, this.retryCount - 1), 600);
    this.logger.warn({ retryCount: this.retryCount, delaySec }, "Scheduling retry");
    this.retryTimeout = setTimeout(() => {
      this.retryTimeout = null;
      this.start().catch((err) =>
        this.logger.error({ err } as Record<string, unknown>, "Retry failed"),
      );
    }, delaySec * 1000);
  }

  private cancelRetry(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }
  }

  // ============================================================
  // Helpers
  // ============================================================

  private getSetting(key: string): string | undefined {
    return this.settingsManager.get(`${SETTINGS_PREFIX}${key}`);
  }
}

// ============================================================
// Plugin entry point
// ============================================================

export function createPlugin(deps: PluginDeps): IntegrationPlugin {
  return new NetatmoWeatherPlugin(deps);
}
