import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NetatmoBridge, PollFailureTracker } from "./index.js";

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
