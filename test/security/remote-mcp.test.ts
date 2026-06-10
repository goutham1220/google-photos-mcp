/**
 * Security tests for the hardened remote-MCP deployment surface:
 *  - MCP-transport bearer auth (StaticUserOAuthProvider + requireBearerAuth)
 *  - READ_ONLY_MODE tool gating (tools/list hides + tools/call rejects writes)
 *  - seedTokensFromEnv (env-seeded refresh token for ephemeral filesystems)
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import request from "supertest";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { StaticUserOAuthProvider } from "../../src/mcpAuth.js";

// Silence winston so test output stays clean.
vi.mock("../../src/utils/logger.js", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// Mock the token store so core/seed tests never touch the native SQLite binary.
vi.mock("../../src/auth/tokens.js", () => ({
  getFirstAvailableTokens: vi.fn(),
  saveTokens: vi.fn(),
}));

const WRITE_TOOLS = [
  "create_album",
  "upload_media",
  "add_media_to_album",
  "add_album_enrichment",
  "set_album_cover",
  "create_album_with_media",
];

describe("MCP-transport bearer auth", () => {
  const BEARER = "test-bearer-secret-value";
  let app: express.Express;

  beforeAll(() => {
    const provider = new StaticUserOAuthProvider(BEARER);
    app = express();
    app.use(express.json());

    const issuerUrl = new URL("http://localhost:3000");
    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl,
        resourceServerUrl: new URL("/mcp", issuerUrl),
        scopesSupported: ["mcp"],
        resourceName: "google-photos-mcp-test",
      }),
    );
    const resourceMetadataUrl = new URL(
      "/.well-known/oauth-protected-resource/mcp",
      issuerUrl,
    ).toString();
    const requireAuth = requireBearerAuth({
      verifier: provider,
      resourceMetadataUrl,
    });
    // Stand-in for the real /mcp transport handler.
    app.post("/mcp", requireAuth, (_req, res) => {
      res.json({ ok: true });
    });
  });

  it("rejects /mcp with no Authorization header (401)", async () => {
    const res = await request(app)
      .post("/mcp")
      .send({ jsonrpc: "2.0", method: "ping", id: 1 });
    expect(res.status).toBe(401);
  });

  it("rejects /mcp with an incorrect bearer token (401)", async () => {
    const res = await request(app)
      .post("/mcp")
      .set("Authorization", "Bearer wrong-token")
      .send({ jsonrpc: "2.0", method: "ping", id: 1 });
    expect(res.status).toBe(401);
  });

  it("accepts /mcp with the correct bearer token (200)", async () => {
    const res = await request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${BEARER}`)
      .send({ jsonrpc: "2.0", method: "ping", id: 1 });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it("exposes OAuth discovery metadata for the connector handshake", async () => {
    const res = await request(app).get(
      "/.well-known/oauth-authorization-server",
    );
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("authorization_endpoint");
    expect(res.body).toHaveProperty("token_endpoint");
  });
});

describe("READ_ONLY_MODE tool gating", () => {
  beforeEach(() => {
    vi.resetModules();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  async function loadCore(readOnly: boolean) {
    vi.stubEnv("READ_ONLY_MODE", readOnly ? "true" : "false");
    vi.resetModules();
    const { GooglePhotosMCPCore } = await import("../../src/mcp/core.js");
    class TestCore extends GooglePhotosMCPCore {
      listToolsForTest() {
        return this.handleListTools();
      }
      callToolForTest(req: CallToolRequest) {
        return this.handleCallTool(req);
      }
    }
    return new TestCore({ name: "test", version: "0.0.0" });
  }

  it("hides write tools from tools/list when read-only", async () => {
    const core = await loadCore(true);
    const { tools } = await core.listToolsForTest();
    const names = tools.map((t) => t.name);
    for (const w of WRITE_TOOLS) {
      expect(names).not.toContain(w);
    }
    // Read tools remain available.
    expect(names).toContain("list_albums");
    expect(names).toContain("search_photos");
    expect(names).toContain("auth_status");
  });

  it("keeps write tools in tools/list when NOT read-only", async () => {
    const core = await loadCore(false);
    const { tools } = await core.listToolsForTest();
    const names = tools.map((t) => t.name);
    expect(names).toContain("upload_media");
    expect(names).toContain("create_album");
  });

  it("rejects a write tool in tools/call when read-only", async () => {
    const core = await loadCore(true);
    const res = (await core.callToolForTest({
      method: "tools/call",
      params: { name: "upload_media", arguments: {} },
    })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res)).toContain("READ_ONLY_MODE");
  });
});

describe("seedTokensFromEnv", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("seeds a refresh token when env is set and the store is empty", async () => {
    vi.stubEnv("GOOGLE_REFRESH_TOKEN", "rt-from-env");
    const tokens = await import("../../src/auth/tokens.js");
    vi.mocked(tokens.getFirstAvailableTokens).mockResolvedValue(null);

    const { seedTokensFromEnv } = await import("../../src/auth/seedFromEnv.js");
    const seeded = await seedTokensFromEnv();

    expect(seeded).toBe(true);
    expect(tokens.saveTokens).toHaveBeenCalledWith(
      "default",
      expect.objectContaining({
        refresh_token: "rt-from-env",
        access_token: "",
        expiry_date: 0,
        userId: "default",
      }),
    );
  });

  it("no-ops when a credential already exists", async () => {
    vi.stubEnv("GOOGLE_REFRESH_TOKEN", "rt-from-env");
    const tokens = await import("../../src/auth/tokens.js");
    vi.mocked(tokens.getFirstAvailableTokens).mockResolvedValue({
      access_token: "existing-access",
      refresh_token: "existing-refresh",
      expiry_date: 9999999999999,
      userId: "default",
    });

    const { seedTokensFromEnv } = await import("../../src/auth/seedFromEnv.js");
    const seeded = await seedTokensFromEnv();

    expect(seeded).toBe(false);
    expect(tokens.saveTokens).not.toHaveBeenCalled();
  });

  it("no-ops when GOOGLE_REFRESH_TOKEN is not set", async () => {
    vi.stubEnv("GOOGLE_REFRESH_TOKEN", "");
    const tokens = await import("../../src/auth/tokens.js");

    const { seedTokensFromEnv } = await import("../../src/auth/seedFromEnv.js");
    const seeded = await seedTokensFromEnv();

    expect(seeded).toBe(false);
    expect(tokens.getFirstAvailableTokens).not.toHaveBeenCalled();
    expect(tokens.saveTokens).not.toHaveBeenCalled();
  });
});
