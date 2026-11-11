import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { ContaShare, ContaShareError, verifyWebhookSignature } from '../src/index.js';

/**
 * A fetch that answers from a list in turn and records each request.
 */
function fakeFetch(...answers) {
  const calls = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    const [status, body] = answers.shift();

    return { status, json: async () => body };
  };

  return { fetch, calls };
}

function client(fetch) {
  return new ContaShare({
    clientId: 'client-123',
    clientSecret: 'secret-456',
    redirectUri: 'https://acme.example/auth/contashare/callback',
    fetch,
  });
}

test('sends people to the consent screen with the app details and state', () => {
  const url = new URL(client(fakeFetch().fetch).authorizeUrl({ state: 'random-state' }));

  assert.equal(url.origin + url.pathname, 'https://contashare.com/oauth/authorize');
  assert.equal(url.searchParams.get('client_id'), 'client-123');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://acme.example/auth/contashare/callback');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('state'), 'random-state');
  assert.equal(url.searchParams.has('reconfirm'), false);
});

test('reconfirm shows the consent screen again, and a state is required', () => {
  const contashare = client(fakeFetch().fetch);

  assert.equal(new URL(contashare.authorizeUrl({ state: 's', reconfirm: true })).searchParams.get('reconfirm'), 'true');
  assert.throws(() => contashare.authorizeUrl({}), TypeError);
});

test('swaps the code for tokens with the client credentials', async () => {
  const { fetch, calls } = fakeFetch([200, { access_token: 'access-1', refresh_token: 'refresh-1', expires_in: 31536000 }]);

  const tokens = await client(fetch).exchangeCode('the-code');

  assert.equal(tokens.access_token, 'access-1');
  assert.equal(calls[0].url, 'https://contashare.com/oauth/token');
  assert.equal(calls[0].method, 'POST');
  assert.deepEqual(Object.fromEntries(calls[0].body), {
    client_id: 'client-123',
    client_secret: 'secret-456',
    grant_type: 'authorization_code',
    code: 'the-code',
    redirect_uri: 'https://acme.example/auth/contashare/callback',
  });
});

test('refreshing swaps the pair, and a refused refresh throws with the reason', async () => {
  const { fetch, calls } = fakeFetch(
    [200, { access_token: 'access-2', refresh_token: 'refresh-2' }],
    [400, { error: 'invalid_grant', error_description: 'The refresh token is invalid.' }],
  );
  const contashare = client(fetch);

  assert.equal((await contashare.refresh('refresh-1')).refresh_token, 'refresh-2');
  assert.equal(Object.fromEntries(calls[0].body).grant_type, 'refresh_token');
  await assert.rejects(contashare.refresh('refresh-1'), (error) => error instanceof ContaShareError && error.status === 400 && error.body.error === 'invalid_grant');
});

test('me returns the id the company knows the customer by, asking for JSON with the token', async () => {
  const { fetch, calls } = fakeFetch([200, { id: '9f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f' }]);

  assert.equal(await client(fetch).me('access-1'), '9f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f');
  assert.equal(calls[0].url, 'https://contashare.com/api/v1/me');
  assert.equal(calls[0].headers.Authorization, 'Bearer access-1');
  assert.equal(calls[0].headers.Accept, 'application/json');
});

test('shared data returns the records once, null when there is nothing new, and throws when refused', async () => {
  const { fetch } = fakeFetch(
    [200, { emails: [{ id: 'email-1' }] }],
    [403, { error: 'You have already fetched bulk shared data for this customer.' }],
    [403, { message: 'Your credits have run out.' }],
  );
  const contashare = client(fetch);

  assert.deepEqual((await contashare.sharedData('access-1')).emails, [{ id: 'email-1' }]);
  assert.equal(await contashare.sharedData('access-1'), null);
  await assert.rejects(contashare.sharedData('access-1'), /Your credits have run out/);
});

test('get follows a webhook resource_url as it is', async () => {
  const { fetch, calls } = fakeFetch([200, { id: 'address-1' }]);

  await client(fetch).get('https://contashare.com/api/v1/address/address-1', 'access-1');

  assert.equal(calls[0].url, 'https://contashare.com/api/v1/address/address-1');
});

test('a base url points it at another ContaShare', () => {
  const contashare = new ContaShare({ clientId: 'c', clientSecret: 's', redirectUri: 'http://localhost/cb', baseUrl: 'http://localhost:8000/' });

  assert.ok(contashare.authorizeUrl({ state: 's' }).startsWith('http://localhost:8000/oauth/authorize?'));
});

test('a webhook signature made with the secret over the raw body is valid, and anything else is not', () => {
  const body = '{"id":"9b3f8a2e","type":"address","action":"update"}';
  const signature = createHmac('sha256', 'whsec').update(body).digest('hex');

  assert.equal(verifyWebhookSignature(body, signature, 'whsec'), true);
  assert.equal(verifyWebhookSignature(Buffer.from(body), signature, 'whsec'), true);
  assert.equal(verifyWebhookSignature(body, signature, 'another-secret'), false);
  assert.equal(verifyWebhookSignature(body.replace('update', 'delete'), signature, 'whsec'), false);
  assert.equal(verifyWebhookSignature(body, undefined, 'whsec'), false);
  assert.equal(verifyWebhookSignature(body, 'short', 'whsec'), false);
});
