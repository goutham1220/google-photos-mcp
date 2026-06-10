#!/usr/bin/env node
/**
 * Prints ONLY the `refresh_token` of the most-recently-saved local credential
 * to stdout. All diagnostics go to stderr, so stdout stays clean for capture.
 *
 * Use this to grab a locally-minted (e.g. read-only) Google refresh token and
 * paste it into Render's `GOOGLE_REFRESH_TOKEN` env var.
 *
 * Usage:
 *   npm run print-refresh-token
 *   npm run print-refresh-token > /tmp/refresh-token.txt   # capture only stdout
 */
import { getFirstAvailableTokens } from "../src/auth/tokens.js";

async function main(): Promise<void> {
  const tokens = await getFirstAvailableTokens();
  if (!tokens || !tokens.refresh_token) {
    process.stderr.write(
      "No refresh token found. Authenticate locally first " +
        "(npm start, then visit http://localhost:3000/auth).\n",
    );
    process.exit(1);
  }
  process.stdout.write(`${tokens.refresh_token}\n`);
}

main().catch((err) => {
  process.stderr.write(
    `${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(1);
});
