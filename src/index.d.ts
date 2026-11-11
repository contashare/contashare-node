export declare const DEFAULT_BASE_URL: string;

export interface TokenResponse {
  token_type: 'Bearer';
  expires_in: number;
  access_token: string;
  refresh_token: string;
}

export declare class ContaShareError extends Error {
  status: number;
  body: unknown;
}

export declare class ContaShare {
  constructor(options: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    baseUrl?: string;
    fetch?: typeof fetch;
  });
  authorizeUrl(options: { state: string; reconfirm?: boolean }): string;
  exchangeCode(code: string): Promise<TokenResponse>;
  refresh(refreshToken: string): Promise<TokenResponse>;
  me(accessToken: string): Promise<string>;
  sharedData(accessToken: string): Promise<Record<string, unknown[]> | null>;
  get<T = unknown>(pathOrUrl: string, accessToken: string): Promise<T>;
}

export declare function verifyWebhookSignature(rawBody: string | Buffer, signature: string | null | undefined, secret: string): boolean;
