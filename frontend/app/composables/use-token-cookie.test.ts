import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import {
  getTokenCookieOptions,
  getTokenSecondsRemaining,
  readTokenCookie,
  shouldRenewToken,
  writeTokenCookie,
} from "./use-token-cookie";

/** Builds an unsigned JWT — only the payload is ever read on the frontend. */
function makeToken(claims: Record<string, unknown>) {
  const encode = (value: object) =>
    btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  return `${encode({ alg: "HS256" })}.${encode(claims)}.signature`;
}

function setLocation(protocol: string) {
  Object.defineProperty(window, "location", {
    value: { ...window.location, protocol },
    configurable: true,
    writable: true,
  });
}

function setFramed(framed: boolean) {
  Object.defineProperty(window, "top", {
    value: framed ? ({} as Window) : window,
    configurable: true,
  });
}

function stubNuxtApp(production: boolean, tokenTime: unknown = 48) {
  vi.stubGlobal("useNuxtApp", () => ({
    $appInfo: { production, tokenTime },
  }));
}

describe("getTokenCookieOptions", () => {
  beforeEach(() => {
    setFramed(false);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("top-level https connection gets a lax, non-partitioned cookie", () => {
    stubNuxtApp(true);
    setLocation("https:");
    setFramed(false);

    const options = getTokenCookieOptions();

    expect(options.secure).toBe(true);
    expect(options.sameSite).toBe("lax");
    expect(options.partitioned).toBe(false);
  });

  test("iframe-embedded https connection gets a none, partitioned cookie", () => {
    stubNuxtApp(true);
    setLocation("https:");
    setFramed(true);

    const options = getTokenCookieOptions();

    expect(options.secure).toBe(true);
    expect(options.sameSite).toBe("none");
    expect(options.partitioned).toBe(true);
  });

  test("insecure (http) connection stays lax and non-partitioned even when framed", () => {
    stubNuxtApp(true);
    setLocation("http:");
    setFramed(true);

    const options = getTokenCookieOptions();

    expect(options.secure).toBe(false);
    expect(options.sameSite).toBe("lax");
    expect(options.partitioned).toBe(false);
  });

  test("non-production build stays lax and non-partitioned even when framed over https", () => {
    stubNuxtApp(false);
    setLocation("https:");
    setFramed(true);

    const options = getTokenCookieOptions();

    expect(options.secure).toBe(false);
    expect(options.sameSite).toBe("lax");
    expect(options.partitioned).toBe(false);
  });
});

describe("getTokenCookieOptions maxAge", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("derives maxAge from the backend's tokenTime", () => {
    stubNuxtApp(true, 720);
    setLocation("https:");

    expect(getTokenCookieOptions().maxAge).toBe(720 * 60 * 60);
  });

  test.each([undefined, null, 0, -1, "abc"])(
    "falls back to a real maxAge instead of NaN when tokenTime is %p",
    (tokenTime) => {
      stubNuxtApp(true, tokenTime);
      setLocation("https:");

      const { maxAge } = getTokenCookieOptions();

      expect(Number.isFinite(maxAge)).toBe(true);
      expect(maxAge).toBe(48 * 60 * 60);
    },
  );
});

describe("getTokenSecondsRemaining", () => {
  const now = 1_700_000_000_000;

  test("returns the seconds left before the token expires", () => {
    const token = makeToken({ exp: now / 1000 + 3600 });

    expect(getTokenSecondsRemaining(token, now)).toBe(3600);
  });

  test("clamps an already-expired token to zero", () => {
    const token = makeToken({ exp: now / 1000 - 3600 });

    expect(getTokenSecondsRemaining(token, now)).toBe(0);
  });

  test.each(["", "not-a-jwt", "a.b"])("returns null for unusable token %p", (token) => {
    expect(getTokenSecondsRemaining(token, now)).toBeNull();
  });
});

describe("shouldRenewToken", () => {
  const now = 1_700_000_000_000;
  const thirtyDays = 30 * 24 * 60 * 60;

  test("leaves a freshly issued token alone", () => {
    const token = makeToken({ exp: now / 1000 + thirtyDays, dur: thirtyDays });

    expect(shouldRenewToken(token, now)).toBe(false);
  });

  test("renews once a quarter of the session has elapsed", () => {
    const token = makeToken({ exp: now / 1000 + thirtyDays * 0.7, dur: thirtyDays });

    expect(shouldRenewToken(token, now)).toBe(true);
  });

  test("does not renew an already-expired token", () => {
    const token = makeToken({ exp: now / 1000 - 1, dur: thirtyDays });

    expect(shouldRenewToken(token, now)).toBe(false);
  });

  test("renews a legacy token that predates the duration claim", () => {
    const token = makeToken({ exp: now / 1000 + thirtyDays });

    expect(shouldRenewToken(token, now)).toBe(true);
  });
});

describe("writeTokenCookie", () => {
  // document.cookie is intercepted rather than using jsdom's cookie jar, which other suites in
  // this project mutate (and which is tied to a window.location these tests replace).
  let written: string[];

  beforeEach(() => {
    written = [];
    setFramed(false);
    setLocation("http:");
    stubNuxtApp(false, 48);
    vi.spyOn(document, "cookie", "set").mockImplementation(value => void written.push(value));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("keeps the cookie alive for as long as the token itself is valid", () => {
    const thirtyDays = 30 * 24 * 60 * 60;
    const token = makeToken({ exp: Date.now() / 1000 + thirtyDays, dur: thirtyDays });

    writeTokenCookie("mealie.access_token", token);

    // TOKEN_TIME is 48h here, so a cookie sized from tokenTime would expire 28 days early.
    expect(written[0]).toContain(`Max-Age=${thirtyDays}`);
    expect(written[0]).toContain(`mealie.access_token=${token}`);
  });

  test("falls back to the configured tokenTime when the token has no expiry", () => {
    writeTokenCookie("mealie.access_token", "not-a-jwt");

    expect(written[0]).toContain(`Max-Age=${48 * 60 * 60}`);
  });

  test("marks the cookie secure and partitioned when embedded over https", () => {
    stubNuxtApp(true, 48);
    setLocation("https:");
    setFramed(true);

    writeTokenCookie("mealie.access_token", makeToken({ exp: Date.now() / 1000 + 3600 }));

    expect(written[0]).toContain("Secure");
    expect(written[0]).toContain("Partitioned");
    expect(written[0]).toContain("SameSite=none");
  });

  test("expires the cookie immediately when clearing it", () => {
    writeTokenCookie("mealie.access_token", null);

    expect(written[0]).toContain("Max-Age=0");
    expect(written[0]).toContain("mealie.access_token=;");
  });
});

describe("readTokenCookie", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function stubCookieHeader(header: string) {
    vi.spyOn(document, "cookie", "get").mockReturnValue(header);
  }

  test("reads the token out of a header containing other cookies", () => {
    const token = makeToken({ exp: Date.now() / 1000 + 3600 });
    stubCookieHeader(`foo=bar; mealie.access_token=${token}; baz=qux`);

    expect(readTokenCookie("mealie.access_token")).toBe(token);
  });

  test("does not match a cookie whose name merely ends with the same text", () => {
    stubCookieHeader("not_mealie.access_token=nope");

    expect(readTokenCookie("mealie.access_token")).toBeNull();
  });

  test("returns null when the cookie is absent or empty", () => {
    stubCookieHeader("mealie.access_token=; other=1");

    expect(readTokenCookie("mealie.access_token")).toBeNull();
  });
});
