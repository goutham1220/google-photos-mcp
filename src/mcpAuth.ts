import crypto from "node:crypto";
import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

/**
 * MCP-transport OAuth provider (Claude -> this MCP server).
 *
 * This is DISTINCT from src/auth/ (which handles Google OAuth: this MCP ->
 * Google). It implements the minimal OAuth 2.1 authorization-code + refresh
 * flows that claude.ai's connector performs during discovery, but ultimately
 * gates every request on a single static bearer (`MCP_BEARER_TOKEN`). Any caller
 * presenting that bearer is accepted; the dynamic-client-registration and
 * authorization-code dance exists only so the connector's OAuth handshake
 * succeeds.
 *
 * Ported from the cronometer-mcp remote MCP pattern.
 */

type StoredAuthCode = {
  client_id: string;
  code_challenge: string;
  redirect_uri: string;
  resource?: string;
  expires_at: number;
};

type StoredAccessToken = {
  client_id: string;
  scopes: string[];
  expires_at: number;
};

type StoredRefreshToken = {
  client_id: string;
  scopes: string[];
};

const ACCESS_TTL_S = 60 * 60 * 24 * 30; // 30 days
const CODE_TTL_S = 60 * 5; // 5 minutes

function rand(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("hex");
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

class InMemoryClientStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  async registerClient(
    client: Omit<
      OAuthClientInformationFull,
      "client_id" | "client_id_issued_at"
    >,
  ): Promise<OAuthClientInformationFull> {
    const client_id = `mcp-${rand(8)}`;
    const stored: OAuthClientInformationFull = {
      ...client,
      client_id,
      client_id_issued_at: nowSec(),
    };
    this.clients.set(client_id, stored);
    return stored;
  }
}

/**
 * An OAuthServerProvider whose access decision reduces to a single static
 * bearer. The standard OAuth endpoints are implemented so MCP clients can
 * complete their discovery + token handshake, but `verifyAccessToken` accepts
 * the configured static bearer directly.
 */
export class StaticUserOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientStore();
  private codes = new Map<string, StoredAuthCode>();
  private accessTokens = new Map<string, StoredAccessToken>();
  private refreshTokens = new Map<string, StoredRefreshToken>();

  /**
   * @param staticBearer The shared secret that grants access. Defaults to the
   *   `MCP_BEARER_TOKEN` env var, read at construction time (i.e. at server
   *   boot, after env is loaded). Passed explicitly in tests.
   */
  constructor(
    private readonly staticBearer: string = process.env.MCP_BEARER_TOKEN ?? "",
  ) {}

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    const code = rand(24);
    this.codes.set(code, {
      client_id: client.client_id,
      code_challenge: params.codeChallenge,
      redirect_uri: params.redirectUri,
      resource: params.resource?.toString(),
      expires_at: nowSec() + CODE_TTL_S,
    });

    const url = new URL(params.redirectUri);
    url.searchParams.set("code", code);
    if (params.state) url.searchParams.set("state", params.state);
    res.redirect(302, url.toString());
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const stored = this.codes.get(authorizationCode);
    if (!stored) throw new Error("Invalid authorization code");
    if (stored.expires_at < nowSec()) {
      this.codes.delete(authorizationCode);
      throw new Error("Authorization code expired");
    }
    return stored.code_challenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const stored = this.codes.get(authorizationCode);
    if (!stored) throw new Error("Invalid authorization code");
    this.codes.delete(authorizationCode);
    if (stored.expires_at < nowSec())
      throw new Error("Authorization code expired");
    if (stored.client_id !== client.client_id)
      throw new Error("Code/client mismatch");
    if (redirectUri && stored.redirect_uri !== redirectUri) {
      throw new Error("redirect_uri mismatch");
    }
    return this.issueTokens(client.client_id, ["mcp"]);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const stored = this.refreshTokens.get(refreshToken);
    if (!stored) throw new Error("Invalid refresh token");
    if (stored.client_id !== client.client_id)
      throw new Error("Refresh/client mismatch");
    this.refreshTokens.delete(refreshToken);
    return this.issueTokens(client.client_id, scopes ?? stored.scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    if (this.staticBearer && token === this.staticBearer) {
      return {
        token,
        clientId: "static-bearer",
        scopes: ["mcp"],
        expiresAt: nowSec() + ACCESS_TTL_S,
      };
    }
    const stored = this.accessTokens.get(token);
    // Throw InvalidTokenError (not a plain Error) so requireBearerAuth maps
    // invalid/expired tokens to 401 rather than 500.
    if (!stored) throw new InvalidTokenError("Invalid access token");
    if (stored.expires_at < nowSec()) {
      this.accessTokens.delete(token);
      throw new InvalidTokenError("Access token expired");
    }
    return {
      token,
      clientId: stored.client_id,
      scopes: stored.scopes,
      expiresAt: stored.expires_at,
    };
  }

  private issueTokens(clientId: string, scopes: string[]): OAuthTokens {
    const access_token = rand(32);
    const refresh_token = rand(32);
    const expires_at = nowSec() + ACCESS_TTL_S;
    this.accessTokens.set(access_token, {
      client_id: clientId,
      scopes,
      expires_at,
    });
    this.refreshTokens.set(refresh_token, { client_id: clientId, scopes });
    return {
      access_token,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_S,
      refresh_token,
      scope: scopes.join(" "),
    };
  }
}
