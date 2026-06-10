import { getFirstAvailableTokens, saveTokens } from "./tokens.js";
import logger from "../utils/logger.js";

/**
 * Seed the local token store from a `GOOGLE_REFRESH_TOKEN` env var.
 *
 * Render free instances have an ephemeral filesystem (wiped on every deploy and
 * spin-down), so the on-disk `tokens.db` does not survive. To keep a cloud
 * deployment authenticated, this seeds a refresh-token-only credential at boot.
 * The seeded record carries `access_token: ""` and `expiry_date: 0`, which
 * forces `tokenRefreshManager.refreshIfNeeded` (via `getAuthenticatedClient`) to
 * mint a fresh access token on the first tool call — reusing the existing Google
 * refresh path, with no new Google API code here.
 *
 * No-ops when:
 *  - `GOOGLE_REFRESH_TOKEN` is not set (local dev / STDIO), or
 *  - a credential with a refresh token already exists in the store (so we never
 *    clobber a locally-authenticated, possibly write-capable token).
 *
 * @returns true if a token was seeded, false otherwise.
 */
export async function seedTokensFromEnv(): Promise<boolean> {
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  if (!refreshToken) {
    return false;
  }

  const existing = await getFirstAvailableTokens();
  if (existing && existing.refresh_token) {
    logger.info(
      "GOOGLE_REFRESH_TOKEN is set but a stored token already exists; skipping env seed.",
    );
    return false;
  }

  const userId = "default";
  await saveTokens(userId, {
    access_token: "",
    refresh_token: refreshToken,
    expiry_date: 0,
    userId,
    retrievedAt: Date.now(),
  });

  logger.info(
    "Seeded refresh token from GOOGLE_REFRESH_TOKEN; access token will be minted on first tool call.",
  );
  return true;
}
