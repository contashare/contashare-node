import { createHmac, timingSafeEqual } from 'node:crypto';

export const DEFAULT_BASE_URL = 'https://contashare.com';

/**
 * Thrown when ContaShare answers with an error. `status` and `body` hold what it said.
 */
export class ContaShareError extends Error {
  constructor(status, body) {
    super(`ContaShare answered ${status}: ${body?.message ?? body?.error ?? body?.error_description ?? ''}`.trim());
    this.name = 'ContaShareError';
    this.status = status;
    this.body = body;
  }
}

/**
 * "Sign in with ContaShare" and the ContaShare API, for one OAuth client.
 */
export class ContaShare {
  /**
   * @param {{clientId: string, clientSecret: string, redirectUri: string, baseUrl?: string, fetch?: typeof fetch}} options
   */
  constructor({ clientId, clientSecret, redirectUri, baseUrl = DEFAULT_BASE_URL, fetch: fetchImplementation = globalThis.fetch }) {
    if (!clientId || !clientSecret || !redirectUri) {
      throw new TypeError('ContaShare needs clientId, clientSecret and redirectUri.');
    }

    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetch = fetchImplementation;
  }

  /**
   * Where to send someone to sign in. Store `state` in their session and check it in your callback.
   * `reconfirm` shows the consent screen again, so they can share something new.
   */
  authorizeUrl({ state, reconfirm = false }) {
    if (!state) {
      throw new TypeError('authorizeUrl needs a state: a random value you store in the session and check in your callback.');
    }

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: '',
      state,
    });

    if (reconfirm) {
      params.set('reconfirm', 'true');
    }

    return `${this.baseUrl}/oauth/authorize?${params}`;
  }

  /**
   * Swaps the code from your callback for an access and refresh token. Do it once, straight away, on your server.
   */
  exchangeCode(code) {
    return this.#token({ grant_type: 'authorization_code', code, redirect_uri: this.redirectUri });
  }

  /**
   * Swaps a refresh token for a new pair. The old pair stops working, so store the new one straight away.
   */
  refresh(refreshToken) {
    return this.#token({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  /**
   * The ID your company knows this customer by. Free. It never changes, it is the same for all your team's OAuth clients,
   * and another company gets a different one for the same person: store it and find the customer by it.
   */
  async me(accessToken) {
    return (await this.get('/api/v1/me', accessToken)).id;
  }

  /**
   * Everything the customer shares with you (1 credit). It answers once per customer, then only again when they have
   * shared something new: null means there is nothing new, so use the list endpoints instead.
   */
  async sharedData(accessToken) {
    const response = await this.#request('/api/v1/shared-data', accessToken);

    if (response.status === 403 && response.body?.error) {
      return null;
    }

    return this.#bodyOrThrow(response);
  }

  /**
   * Any API endpoint, such as a webhook's `resource_url` or '/api/v1/email'.
   */
  async get(pathOrUrl, accessToken) {
    return this.#bodyOrThrow(await this.#request(pathOrUrl, accessToken));
  }

  async #request(pathOrUrl, accessToken) {
    const url = pathOrUrl.startsWith('http') ? pathOrUrl : `${this.baseUrl}${pathOrUrl}`;
    // Without Accept: application/json, ContaShare redirects an unauthorised call to its login page instead of a 401.
    const response = await this.fetch(url, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}` },
    });

    return { status: response.status, body: await response.json().catch(() => null) };
  }

  async #token(fields) {
    const response = await this.fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, ...fields }),
    });

    return this.#bodyOrThrow({ status: response.status, body: await response.json().catch(() => null) });
  }

  #bodyOrThrow({ status, body }) {
    if (status < 200 || status >= 300) {
      throw new ContaShareError(status, body);
    }

    return body;
  }
}

/**
 * Checks the `Signature` header ContaShare sends with every webhook: the HMAC-SHA256 (hex) of the raw request body, keyed
 * with your webhook secret. Pass the raw body as a string or Buffer, never JSON you parsed and stringified again.
 */
export function verifyWebhookSignature(rawBody, signature, secret) {
  if (!signature || !secret || rawBody === undefined || rawBody === null) {
    return false;
  }

  const expected = Buffer.from(createHmac('sha256', secret).update(rawBody).digest('hex'));
  const given = Buffer.from(String(signature));

  return expected.length === given.length && timingSafeEqual(expected, given);
}
