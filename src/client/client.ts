import {
  APIAction,
  APICommandPayloadMap,
  APIResponseMap,
  ChallengeResponseData,
  ErrorResponse,
  OAuthConfig,
  OAuthProvider,
  OnSessionUpdateHandler,
  Session,
  SessionResponse,
} from "../types";
import {
  parseToken,
  generateChallenge,
  generateRandom,
  generateState,
} from "../utils";
import * as storage from "./storage";

class AuthClient {
  private url: string | URL;
  private oauth: OAuthConfig | null;
  private listeners: OnSessionUpdateHandler[];
  private status: "ready" | "loading";
  challenge: ChallengeResponseData | null;
  session: Session | null;

  constructor(apiUrl: string | URL, oauthConfig?: OAuthConfig) {
    this.url = apiUrl;
    this.session = null;
    this.listeners = [];
    this.challenge = null;
    this.oauth = oauthConfig ?? null;
    this.status = "ready";
  }

  private request = async <T extends APIAction>(
    action: T,
    payload: APICommandPayloadMap[T],
  ): Promise<APIResponseMap[T]> => {
    try {
      this.status = "loading";
      const headers = new Headers();
      headers.set("Content-Type", "application/json");
      headers.set("Accept", "application/json");
      headers.set("X-Auth-Action", action);

      const response = await fetch(this.url, {
        method: "POST",
        headers: headers,
        body: JSON.stringify(payload ?? {}),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error);
      }

      if ("challenge" in data) {
        this.challenge = data.challenge;
      }

      if ("session" in data) {
        storage.setChallengeSession(data.session);
      }

      return data;
    } finally {
      this.status = "ready";
    }
  };

  private isValidSession = (session: Session) => {
    if (!session.isLoggedIn && session.isGuest && session.tokens.guestToken) {
      return true;
    }

    if (session.isLoggedIn && session.isUser && session.tokens.idToken) {
      return session.tokens.tokenValidity > Date.now() + 3e5;
    }

    return false;
  };

  private pushSession = () => {
    if (!this.session) return false;

    for (const listener of this.listeners) {
      listener(this.session);
    }
  };

  public getSession = () => {
    if (!this.session) {
      this.checkSession();
    }

    return this.session;
  };

  public getUserInfo = () => {
    if (!this.session) {
      this.checkSession();
      return null;
    }

    if (!this.session.isLoggedIn || !this.session.tokens.idToken) {
      return null;
    }

    const payload = parseToken(this.session.tokens.idToken);

    return payload;
  };

  protected promiseSession = () => {
    return new Promise<() => void>((resolve) => {
      const unsubscribe = this.onSessionUpdate(() => {
        resolve(unsubscribe);
      });
    });
  };

  public checkSession = async () => {
    let session = this.session;

    if (!session || !this.isValidSession(session)) {
      if (this.status === "loading") {
        const unsubscribe = await this.promiseSession();
        session = this.session;
        unsubscribe();
      } else {
        session = await this.refreshSession();
      }

      if (!session) {
        throw new Error("No session found");
      }
    }

    return session;
  };

  public getAccessToken = async () => {
    const session = await this.checkSession();
    return session.isLoggedIn
      ? session.tokens.accessToken
      : session.tokens.guestToken;
  };

  public getIdToken = async () => {
    const session = await this.checkSession();
    return session.isLoggedIn ? session.tokens.idToken : null;
  };

  public setSession = (session: SessionResponse) => {
    this.session = session;

    this.pushSession();
    return this.session;
  };

  public onSessionUpdate = (handler: OnSessionUpdateHandler) => {
    this.listeners.push(handler);

    return () => {
      this.listeners.splice(this.listeners.indexOf(handler) >>> 0, 1);
    };
  };

  public refreshSession = async () => {
    const response = await this.request("RefreshSession", null);

    if (response.success && response.data) {
      return this.setSession(response.data);
    }

    this.session = null;
    this.pushSession();
    return this.session;
  };

  public createAccount = (
    email: string,
    details: Record<string, string>,
    redirectUrl?: string,
  ) => {
    if (redirectUrl) {
      storage.setRedirectUrl(redirectUrl);
    }

    return this.request("CreateAccount", { username: email, details });
  };

  public confirmAccount = async (username: string, challengeToken: string) => {
    const response = await this.request("ConfirmAccount", {
      username: decodeURIComponent(username),
      token: decodeURIComponent(challengeToken),
    });

    if (response.success && response.data) {
      this.setSession(response.data);
    }

    return { ...response, redirectUrl: storage.getRedirectUrl() };
  };

  public initiateAuth = (email: string, redirectUrl?: string) => {
    if (redirectUrl) {
      storage.setRedirectUrl(redirectUrl);
    }

    return this.request("InitiateAuth", { email });
  };

  public authenticate = async (username: string, challenge: string) => {
    const session = storage.getChallengeSession();
    const redirectUrl = storage.getRedirectUrl();

    if (!session) {
      return {
        success: false,
        error: { code: "InvalidRequest", message: "No session found" },
        redirectUrl,
      };
    }

    const response = await this.request("Authenticate", {
      username: decodeURIComponent(username),
      challenge: decodeURIComponent(challenge),
      session: session,
    });

    if (response.success && response.data) {
      this.setSession(response.data);
    }

    return { ...response, redirectUrl: storage.getRedirectUrl() };
  };

  public socialSignIn = async (
    provider: OAuthProvider,
    redirectUrl?: string,
  ) => {
    if (!this.oauth) {
      return console.error("Missing oauth config");
    }

    if (redirectUrl) {
      storage.setRedirectUrl(redirectUrl);
    }

    const state = generateState(32);
    storage.setState(state);

    const pkce_key = generateRandom(128);
    storage.setPKCE(pkce_key);

    const code_challenge = generateChallenge(pkce_key);
    const code_challenge_method = "S256";

    const scopes = this.oauth.scopes
      ? this.oauth.scopes.join(" ")
      : "email profile openid";

    const queryString = Object.entries({
      redirect_uri: this.oauth.redirectSignIn,
      client_id: this.oauth.clientId,
      identity_provider: provider,
      response_type: "code",
      scope: scopes,
      state,
      code_challenge,
      code_challenge_method,
    })
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    window.open(
      `https://${this.oauth.domain}/oauth2/authorize?${queryString}`,
      "_self",
    );
  };

  public oAuthLogin = async () => {
    if (!this.oauth) {
      return console.error("Missing oauth config");
    }

    const state = generateState(32);
    storage.setState(state);

    const pkce_key = generateRandom(128);
    storage.setPKCE(pkce_key);

    const code_challenge = generateChallenge(pkce_key);
    const code_challenge_method = "S256";

    const scopes = this.oauth.scopes
      ? this.oauth.scopes.join(" ")
      : "email profile openid";

    const queryString = Object.entries({
      redirect_uri: this.oauth.redirectSignIn,
      client_id: this.oauth.clientId,
      response_type: "code",
      scope: scopes,
      state,
      code_challenge,
      code_challenge_method,
    })
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    window.open(`https://${this.oauth.domain}/login?${queryString}`, "_self");
  };

  public authorize = async () => {
    if (!this.oauth) {
      console.error("OAuth not configured");
      return {
        success: false,
        error: { code: "Invalid", message: "OAuth not configured" },
      } as ErrorResponse;
    }

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const pkceKey = storage.getPKCE();
    const savedState = storage.getState();
    const redirectUri = this.oauth.redirectSignIn;

    if (!code || !pkceKey) {
      return {
        success: false,
        error: { code: "Invalid", message: "Invalid request" },
      } as ErrorResponse;
    }

    if (savedState && savedState !== state) {
      return {
        success: false,
        error: { code: "Invalid", message: "Invalid state" },
      } as ErrorResponse;
    }

    const payload = {
      code: code,
      code_verifier: pkceKey,
      redirect_uri: redirectUri,
      client_id: this.oauth.clientId,
      grant_type: "authorization_code",
    };

    const body = Object.entries(payload)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    const response = await fetch(`https://${this.oauth.domain}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    const data = await response.json();
    const { refresh_token, id_token, access_token, error } = data;

    if (error) {
      console.log(error);
      return { success: false, error } as ErrorResponse;
    }

    const tokenData = parseToken(id_token);
    const username = tokenData["cognito:username"];

    const sessionResponse = await this.request("SetSession", {
      userId: username,
      tokens: {
        idToken: id_token,
        accessToken: access_token,
        refreshToken: refresh_token,
      },
    });

    if (sessionResponse.success && sessionResponse.data) {
      this.setSession(sessionResponse.data);
    }

    return { ...sessionResponse, redirectUrl: storage.getRedirectUrl() };
  };

  oAuthLogout = () => {
    if (!this.oauth) {
      return console.error("OAuth not configured");
    }

    const logoutUri = encodeURIComponent(`${this.oauth.redirectSignOut}`);

    return window.open(
      `https://${this.oauth.domain}/logout?client_id=${this.oauth.clientId}&redirect_uri=${logoutUri}`,
      "_self",
    );
  };

  public startLogout = (global = false) => {
    if (global) {
      storage.setGlobalSignOut();
    }

    if (storage.isOAuthUser()) {
      return this.oAuthLogout();
    }

    window.open(`/auth/logout`, "_self");
  };

  public logout = async (global = false) => {
    const response = await this.request("Logout", { global });

    this.session = null;
    this.pushSession();

    return response;
  };

  public verifyEmail = async (challenge: string) => {
    if (!this.session?.isLoggedIn) {
      return { success: false, error: "Not authenticated" };
    }

    return this.request("VerifyEmail", {
      code: challenge,
      token: this.session.tokens.accessToken,
    });
  };
}

export default AuthClient;
