// Fallback matching the backend's own TOKEN_TIME default. Only used when the value from
// /api/app/about is missing or unusable — see getTokenCookieOptions.
const FALLBACK_TOKEN_TIME_HOURS = 48;

export function getTokenCookieOptions() {
  const { $appInfo } = useNuxtApp();

  const isSecureConnection = !!$appInfo?.production && window?.location?.protocol === "https:";
  const isEmbedded = isSecureConnection && window?.self !== window?.top;

  // A missing or non-numeric tokenTime would serialize as `Max-Age=NaN`, which browsers reject
  // and fall back to a session cookie for — silently logging the user out as soon as the browser
  // (or PWA) is closed.
  const tokenTime = Number($appInfo?.tokenTime);
  const maxAge = Number.isFinite(tokenTime) && tokenTime > 0 ? tokenTime : FALLBACK_TOKEN_TIME_HOURS;

  return {
    maxAge: maxAge * 60 * 60,
    secure: isSecureConnection,
    sameSite: (isEmbedded ? "none" : "lax") as "none" | "lax",
    partitioned: isEmbedded,
  };
}

interface TokenClaims {
  /** expiry, in seconds since the epoch */
  exp?: number;
  /** total lifetime this session was granted, in seconds */
  dur?: number;
}

export function decodeTokenClaims(token: string): TokenClaims | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) {
      return null;
    }

    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = `${normalized}${"=".repeat((4 - normalized.length % 4) % 4)}`;
    const claims = JSON.parse(atob(padded));

    return typeof claims === "object" && claims !== null ? claims as TokenClaims : null;
  }
  catch {
    return null;
  }
}

/** Seconds until the token expires, or null when the token carries no usable expiry. */
export function getTokenSecondsRemaining(token: string, now = Date.now()): number | null {
  const exp = decodeTokenClaims(token)?.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) {
    return null;
  }

  return Math.max(Math.floor(exp - now / 1000), 0);
}

/**
 * True once enough of the session has elapsed to be worth renewing.
 *
 * Renewing on every page load would hammer the API, and renewing only near the end of the window
 * would strand anyone who happens not to visit that week. Renewing after a quarter of the session
 * has burned down keeps an active user logged in indefinitely at roughly one call per week on a
 * 30 day session.
 */
export function shouldRenewToken(token: string, now = Date.now()): boolean {
  const claims = decodeTokenClaims(token);
  const remaining = getTokenSecondsRemaining(token, now);
  if (remaining === null || remaining <= 0) {
    return false;
  }

  const granted = claims?.dur;
  if (typeof granted !== "number" || !Number.isFinite(granted) || granted <= 0) {
    // Pre-`dur` token: renew so it picks up a duration claim.
    return true;
  }

  return remaining < granted * 0.75;
}

/**
 * Writes the token cookie directly.
 *
 * `useCookie` bakes `maxAge` in when the ref is created, so it cannot give each token a cookie
 * matching that token's own expiry. Writing here keeps the cookie alive for exactly as long as
 * the JWT inside it is valid — a cookie that dies first logs out a user whose token is still good.
 */
export function writeTokenCookie(name: string, token: string | null) {
  // Deletion is kept free of any $appInfo lookup so it still works from contexts where the Nuxt
  // app instance isn't resolvable (e.g. an axios interceptor handling a 401). Browsers match the
  // cookie to delete on name/path/domain only, so the remaining attributes don't matter here.
  if (token === null) {
    document.cookie = `${name}=; Path=/; Max-Age=0`;
    return;
  }

  const options = getTokenCookieOptions();
  const parts = [
    `${name}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${getTokenSecondsRemaining(token) ?? options.maxAge}`,
    `SameSite=${options.sameSite}`,
  ];

  if (options.secure) {
    parts.push("Secure");
  }
  if (options.partitioned) {
    parts.push("Partitioned");
  }

  document.cookie = parts.join("; ");
}

export function readTokenCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^;]*)`));
  if (!match?.[1]) {
    return null;
  }

  try {
    return decodeURIComponent(match[1]);
  }
  catch {
    return match[1];
  }
}
