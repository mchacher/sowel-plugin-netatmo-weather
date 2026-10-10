import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  NetatmoBridge,
  PollFailureTracker,
  createPlugin,
  nextBackfillWindow,
  parseRainHours,
  recentReadStart,
} from "./index.js";

// ============================================================
// PollFailureTracker (issue #2)
// ============================================================

describe("PollFailureTracker", () => {
  it("raises only when the threshold is reached, once", () => {
    const tracker = new PollFailureTracker(3);
    expect(tracker.recordFailure()).toBe(null);
    expect(tracker.recordFailure()).toBe(null);
    expect(tracker.recordFailure()).toBe("raise");
    expect(tracker.recordFailure()).toBe(null); // already raised
    expect(tracker.consecutiveFailures).toBe(4);
  });

  it("resolves on the first success after a raise", () => {
    const tracker = new PollFailureTracker(2);
    tracker.recordFailure();
    tracker.recordFailure();
    expect(tracker.recordSuccess()).toBe("resolve");
    expect(tracker.consecutiveFailures).toBe(0);
  });

  it("success without a prior raise resolves nothing and resets the count", () => {
    const tracker = new PollFailureTracker(3);
    tracker.recordFailure();
    tracker.recordFailure();
    expect(tracker.recordSuccess()).toBe(null);
    // Counter restarted: threshold is consecutive, not cumulative.
    expect(tracker.recordFailure()).toBe(null);
    expect(tracker.recordFailure()).toBe(null);
    expect(tracker.recordFailure()).toBe("raise");
  });

  it("can raise again after a resolve", () => {
    const tracker = new PollFailureTracker(2);
    tracker.recordFailure();
    expect(tracker.recordFailure()).toBe("raise");
    expect(tracker.recordSuccess()).toBe("resolve");
    tracker.recordFailure();
    expect(tracker.recordFailure()).toBe("raise");
  });
});

// ============================================================
// NetatmoBridge — 401/403 re-refresh and retry (issue #2)
// ============================================================

const silentLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
} as never;

function tokenResponse(suffix: string) {
  return new Response(
    JSON.stringify({
      access_token: `access-${suffix}`,
      refresh_token: `refresh-${suffix}`,
      expires_in: 10800,
    }),
    { status: 200 },
  );
}

function stationsResponse() {
  return new Response(JSON.stringify({ body: { devices: [] }, status: "ok" }), { status: 200 });
}

describe("NetatmoBridge apiGet", () => {
  let tmpDir: string;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "netatmo-test-"));
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function buildBridge(): NetatmoBridge {
    return new NetatmoBridge(
      "cid",
      "csecret",
      "refresh-initial",
      silentLogger,
      join(tmpDir, "tokens.json"),
    );
  }

  it("re-refreshes and retries once when the API returns 403", async () => {
    const bridge = buildBridge();

    // authenticate(): POST /oauth2/token
    fetchMock.mockResolvedValueOnce(tokenResponse("t1"));
    await bridge.authenticate();

    // getStationsData(): GET 403 → POST refresh → GET 200
    fetchMock
      .mockResolvedValueOnce(new Response("Invalid access token", { status: 403 }))
      .mockResolvedValueOnce(tokenResponse("t2"))
      .mockResolvedValueOnce(stationsResponse());

    const data = await bridge.getStationsData();
    expect(data.body.devices).toEqual([]);

    const calls = fetchMock.mock.calls.map((c) => [c[0], (c[1] as RequestInit).method]);
    expect(calls).toEqual([
      ["https://api.netatmo.com/oauth2/token", "POST"],
      ["https://api.netatmo.com/api/getstationsdata", "GET"],
      ["https://api.netatmo.com/oauth2/token", "POST"],
      ["https://api.netatmo.com/api/getstationsdata", "GET"],
    ]);

    // The retried GET must carry the re-refreshed token.
    const lastHeaders = (fetchMock.mock.calls[3][1] as RequestInit).headers as Record<
      string,
      string
    >;
    expect(lastHeaders.Authorization).toBe("Bearer access-t2");

    bridge.disconnect();
  });

  it("does not retry more than once — a second 403 propagates", async () => {
    const bridge = buildBridge();

    fetchMock.mockResolvedValueOnce(tokenResponse("t1"));
    await bridge.authenticate();

    fetchMock
      .mockResolvedValueOnce(new Response("Invalid access token", { status: 403 }))
      .mockResolvedValueOnce(tokenResponse("t2"))
      .mockResolvedValueOnce(new Response("Invalid access token", { status: 403 }));

    await expect(bridge.getStationsData()).rejects.toThrow(/failed \(403\)/);
    expect(fetchMock.mock.calls.length).toBe(4);

    bridge.disconnect();
  });

  it("propagates a failed forced re-refresh (revoked grant)", async () => {
    const bridge = buildBridge();

    fetchMock.mockResolvedValueOnce(tokenResponse("t1"));
    await bridge.authenticate();

    fetchMock
      .mockResolvedValueOnce(new Response("Invalid access token", { status: 403 }))
      .mockResolvedValueOnce(new Response("invalid_grant", { status: 400 }));

    await expect(bridge.getStationsData()).rejects.toThrow(/Token refresh failed \(400\)/);

    bridge.disconnect();
  });

  it("plain non-auth errors do not trigger a re-refresh", async () => {
    const bridge = buildBridge();

    fetchMock.mockResolvedValueOnce(tokenResponse("t1"));
    await bridge.authenticate();

    fetchMock.mockResolvedValueOnce(new Response("server error", { status: 500 }));

    await expect(bridge.getStationsData()).rejects.toThrow(/failed \(500\)/);
    // authenticate POST + single GET, no extra refresh
    expect(fetchMock.mock.calls.length).toBe(2);

    bridge.disconnect();
  });
});

// ============================================================
// Hourly rain (Sowel per-hour contract, sowel#1036)
// ============================================================

const H = 3600;
/** 2026-10-10 10:20:00 UTC; the current hour starts at 10:00. */
const NOW_S = Date.UTC(2026, 9, 10, 10, 20) / 1000;
const CURRENT_HOUR = Date.UTC(2026, 9, 10, 10) / 1000;

describe("parseRainHours", () => {
  it("floors Netatmo's mid-hour stamps to the hour start, oldest first", () => {
    const body = {
      [String(CURRENT_HOUR - H + 1800)]: [0.4],
      [String(CURRENT_HOUR - 2 * H + 1800)]: [1.2],
    };
    expect(parseRainHours(body)).toEqual([
      { hourStart: CURRENT_HOUR - 2 * H, mm: 1.2 },
      { hourStart: CURRENT_HOUR - H, mm: 0.4 },
    ]);
  });

  it("keeps an exact hour stamp on its hour (real_time)", () => {
    expect(parseRainHours({ [String(CURRENT_HOUR)]: [0.1] })).toEqual([
      { hourStart: CURRENT_HOUR, mm: 0.1 },
    ]);
  });

  it("skips hours without a value and anything malformed", () => {
    expect(
      parseRainHours({ [String(CURRENT_HOUR)]: [null], x: [1], [String(CURRENT_HOUR - H)]: "1" }),
    ).toEqual([]);
    expect(parseRainHours(null)).toEqual([]);
    expect(parseRainHours([])).toEqual([]);
  });
});

describe("nextBackfillWindow", () => {
  it("starts with the week before the recent hours", () => {
    const recentStart = CURRENT_HOUR - 3 * H;
    expect(nextBackfillWindow(NOW_S, null)).toEqual({
      begin: recentStart - 168 * H,
      end: recentStart + 1800,
    });
  });

  it("continues before the oldest hour already backfilled", () => {
    const oldest = CURRENT_HOUR - 30 * 86_400;
    expect(nextBackfillWindow(NOW_S, oldest)).toEqual({
      begin: oldest - 168 * H,
      end: oldest + 1800,
    });
  });

  it("stops at 364 days, clamping the last step", () => {
    const limit = CURRENT_HOUR - 364 * 86_400;
    expect(nextBackfillWindow(NOW_S, limit + 10 * H)).toEqual({
      begin: limit,
      end: limit + 10 * H + 1800,
    });
    expect(nextBackfillWindow(NOW_S, limit)).toBeNull();
  });

  it("covers a year in about 52 steps, each reaching half an hour into the previous one", () => {
    let to: number | null = null;
    let steps = 0;
    let previousBegin = Infinity;
    for (let w = nextBackfillWindow(NOW_S, to); w; w = nextBackfillWindow(NOW_S, to)) {
      expect(w.end).toBe((previousBegin === Infinity ? CURRENT_HOUR - 3 * H : previousBegin) + 1800);
      previousBegin = w.begin;
      to = w.begin;
      steps++;
    }
    expect(steps).toBe(52);
  });
});

describe("recentReadStart", () => {
  it("reads the last 3 hours in steady state", () => {
    expect(recentReadStart(NOW_S, null)).toBe(CURRENT_HOUR - 3 * H);
    expect(recentReadStart(NOW_S, CURRENT_HOUR)).toBe(CURRENT_HOUR - 3 * H);
  });

  it("catches up from the newest hour already read after an outage", () => {
    expect(recentReadStart(NOW_S, CURRENT_HOUR - 10 * H)).toBe(CURRENT_HOUR - 10 * H);
  });

  it("never reaches further back than 1000 hours", () => {
    expect(recentReadStart(NOW_S, CURRENT_HOUR - 5000 * H)).toBe(CURRENT_HOUR - 1000 * H);
  });
});

describe("Netatmo Weather plugin — hourly rain", () => {
  let tmpDir: string;
  let fetchMock: ReturnType<typeof vi.fn>;
  const settings = new Map<string, string>();
  const updates: Array<{ device: string; payload: Record<string, unknown>; ts?: number }> = [];

  const rainModule = {
    _id: "05:00:00:00:00:01",
    type: "NAModule3",
    module_name: "Pluviomètre",
    firmware: 1,
    rf_status: 60,
    battery_percent: 80,
    dashboard_data: { Rain: 0.101, sum_rain_1: 0.3, sum_rain_24: 2.1, time_utc: NOW_S - 300 },
  };
  const station = {
    _id: "70:ee:50:00:00:01",
    type: "NAMain",
    station_name: "Maison",
    module_name: "Salon",
    firmware: 1,
    wifi_status: 50,
    dashboard_data: { Temperature: 20 },
    modules: [rainModule],
  };

  function measure(hours: Record<number, number>) {
    const body = Object.fromEntries(
      Object.entries(hours).map(([start, mm]) => [String(Number(start) + 1800), [mm]]),
    );
    return new Response(JSON.stringify({ body, status: "ok" }), { status: 200 });
  }

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW_S * 1000);
    tmpDir = mkdtempSync(join(tmpdir(), "netatmo-plugin-test-"));
    settings.clear();
    updates.length = 0;
    settings.set("integration.netatmo_weather.client_id", "cid");
    settings.set("integration.netatmo_weather.client_secret", "secret");
    settings.set("integration.netatmo_weather.refresh_token", "refresh");
    fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/oauth2/token")) return tokenResponse("t");
      if (url.includes("/api/getstationsdata")) {
        return new Response(JSON.stringify({ body: { devices: [station] }, status: "ok" }), {
          status: 200,
        });
      }
      const q = new URL(url).searchParams;
      if (q.get("date_end")) return measure({ [CURRENT_HOUR - 30 * H]: 5.5 }); // backfill step
      return measure({ [CURRENT_HOUR - 2 * H]: 1.2, [CURRENT_HOUR - H]: 0.4, [CURRENT_HOUR]: 0.1 });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function plugin() {
    return createPlugin({
      logger: { ...(silentLogger as object), child: () => silentLogger } as never,
      eventBus: { emit: () => {} },
      settingsManager: {
        get: (k: string) => settings.get(k),
        set: (k: string, v: string) => void settings.set(k, v),
      },
      deviceManager: {
        upsertFromDiscovery: () => {},
        updateDeviceData: (_i: string, device: string, payload: Record<string, unknown>, ts?: number) =>
          void updates.push({ device, payload, ts }),
        migrateIntegrationId: () => 0,
      },
      pluginDir: join(tmpDir, "plugins", "netatmo_weather"),
    });
  }

  const rainUpdates = () => updates.filter((u) => "rain" in u.payload);

  it("no longer publishes the dashboard's 5-minute Rain", async () => {
    const p = plugin();
    await p.start();
    await p.stop();
    const live = updates.find((u) => u.device === "Pluviomètre" && u.ts === undefined);
    expect(live?.payload).toEqual({ sum_rain_1: 0.3, sum_rain_24: 2.1, battery: 80 });
  });

  it("publishes Netatmo's hourly totals stamped at the hour start, newest last", async () => {
    const p = plugin();
    await p.start();
    await p.stop();
    expect(rainUpdates()).toEqual([
      { device: "Pluviomètre", payload: { rain: 5.5 }, ts: CURRENT_HOUR - 30 * H },
      { device: "Pluviomètre", payload: { rain: 1.2 }, ts: CURRENT_HOUR - 2 * H },
      { device: "Pluviomètre", payload: { rain: 0.4 }, ts: CURRENT_HOUR - H },
      { device: "Pluviomètre", payload: { rain: 0.1 }, ts: CURRENT_HOUR },
    ]);
    const measureCalls = fetchMock.mock.calls
      .map((c) => String(c[0]))
      .filter((u) => u.includes("/api/getmeasure"))
      .map((u) => new URL(u).searchParams);
    expect(measureCalls).toHaveLength(2);
    for (const q of measureCalls) {
      expect(q.get("device_id")).toBe(station._id);
      expect(q.get("module_id")).toBe(rainModule._id);
      expect(q.get("scale")).toBe("1hour");
      expect(q.get("type")).toBe("sum_rain");
    }
  });

  it("records the backfill progress and resumes from it", async () => {
    const p = plugin();
    await p.start();
    const first = Number(settings.get(`integration.netatmo_weather.rain_backfill.${rainModule._id}`));
    expect(first).toBe(CURRENT_HOUR - 3 * H - 168 * H);
    await p.refresh!();
    await p.stop();
    expect(Number(settings.get(`integration.netatmo_weather.rain_backfill.${rainModule._id}`))).toBe(
      first - 168 * H,
    );
  });

  it("resends only changed recent hours on the next poll, always ending on the newest", async () => {
    settings.set(
      `integration.netatmo_weather.rain_backfill.${rainModule._id}`,
      String(CURRENT_HOUR - 364 * 86_400),
    );
    const p = plugin();
    await p.start();
    updates.length = 0;
    await p.refresh!();
    await p.stop();
    expect(rainUpdates()).toEqual([{ device: "Pluviomètre", payload: { rain: 0.1 }, ts: CURRENT_HOUR }]);
  });

  it("keeps polling the other readings when the rain fetch fails", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes("/oauth2/token")) return tokenResponse("t");
      if (url.includes("/api/getstationsdata")) {
        return new Response(JSON.stringify({ body: { devices: [station] }, status: "ok" }), {
          status: 200,
        });
      }
      return new Response("boom", { status: 500 });
    });
    const p = plugin();
    await p.start();
    expect(p.getStatus()).toBe("connected");
    await p.stop();
    expect(rainUpdates()).toHaveLength(0);
    expect(updates.some((u) => u.device === "Pluviomètre")).toBe(true);
  });

  const SETTING = (k: string) => `integration.netatmo_weather.${k}.${rainModule._id}`;
  const measureQueries = () =>
    fetchMock.mock.calls
      .map((c) => String(c[0]))
      .filter((u) => u.includes("/api/getmeasure"))
      .map((u) => new URL(u).searchParams);

  function routes(onMeasure: (q: URLSearchParams) => Response) {
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes("/oauth2/token")) return tokenResponse("t");
      if (url.includes("/api/getstationsdata")) {
        return new Response(JSON.stringify({ body: { devices: [station] }, status: "ok" }), {
          status: 200,
        });
      }
      return onMeasure(new URL(url).searchParams);
    });
  }

  it("still publishes the recent hours when the backfill step fails, and skips it after 3 failures", async () => {
    routes((q) =>
      q.get("date_end")
        ? new Response("range refused", { status: 400 })
        : measure({ [CURRENT_HOUR - H]: 0.4, [CURRENT_HOUR]: 0.1 }),
    );
    const p = plugin();
    await p.start();
    expect(rainUpdates().map((u) => u.ts)).toEqual([CURRENT_HOUR - H, CURRENT_HOUR]);
    expect(settings.get(SETTING("rain_backfill"))).toBeUndefined();
    await p.refresh!();
    expect(settings.get(SETTING("rain_backfill"))).toBeUndefined();
    await p.refresh!();
    await p.stop();
    // third failure: the step is skipped, the next poll moves on
    expect(Number(settings.get(SETTING("rain_backfill")))).toBe(CURRENT_HOUR - 3 * H - 168 * H);
  });

  it("sends an hour once more after it closes, even with the same total", async () => {
    settings.set(SETTING("rain_backfill"), String(CURRENT_HOUR - 364 * 86_400));
    routes(() =>
      measure(
        Date.now() / 1000 < CURRENT_HOUR + H
          ? { [CURRENT_HOUR]: 0.1 }
          : { [CURRENT_HOUR]: 0.1, [CURRENT_HOUR + H]: 0 },
      ),
    );
    const p = plugin();
    await p.start();
    vi.setSystemTime((CURRENT_HOUR + H + 300) * 1000);
    updates.length = 0;
    await p.refresh!();
    await p.stop();
    expect(rainUpdates().map((u) => [u.ts, u.payload.rain])).toEqual([
      [CURRENT_HOUR, 0.1],
      [CURRENT_HOUR + H, 0],
    ]);
  });

  it("catches up the hours missed during an outage", async () => {
    settings.set(SETTING("rain_backfill"), String(CURRENT_HOUR - 364 * 86_400));
    settings.set(SETTING("rain_synced_to"), String(CURRENT_HOUR - 10 * H));
    routes(() => measure({ [CURRENT_HOUR - 9 * H]: 2, [CURRENT_HOUR]: 0.1 }));
    const p = plugin();
    await p.start();
    await p.stop();
    expect(measureQueries()[0].get("date_begin")).toBe(String(CURRENT_HOUR - 10 * H));
    expect(rainUpdates().map((u) => u.ts)).toEqual([CURRENT_HOUR - 9 * H, CURRENT_HOUR]);
    expect(settings.get(SETTING("rain_synced_to"))).toBe(String(CURRENT_HOUR));
  });
});
