# ContaShare for Node.js

Sign in with [ContaShare](https://contashare.com) and read the contact details your customers choose to share with you, plus a
checker for ContaShare webhook signatures. No dependencies: it uses Node's own `fetch` and `crypto` (Node 18 or later).

```bash
npm install contashare
```

## Sign up and sign in

```js
import { randomBytes } from 'node:crypto';
import { ContaShare } from 'contashare';

const contashare = new ContaShare({
  clientId: process.env.CONTASHARE_CLIENT_ID,
  clientSecret: process.env.CONTASHARE_CLIENT_SECRET,
  redirectUri: process.env.CONTASHARE_REDIRECT_URI,
});

app.get('/auth/contashare', (req, res) => {
  req.session.contashareState = randomBytes(20).toString('hex');
  res.redirect(contashare.authorizeUrl({ state: req.session.contashareState }));
});

app.get('/auth/contashare/callback', async (req, res) => {
  const expected = req.session.contashareState;
  delete req.session.contashareState;
  if (!expected || req.query.state !== expected) return res.status(400).send('That link expired. Try again.');
  if (req.query.error) return res.redirect('/login'); // they pressed Cancel

  const tokens = await contashare.exchangeCode(req.query.code);
  const contashareId = await contashare.me(tokens.access_token); // free

  let user = await users.findByContaShareId(contashareId);

  if (!user) {
    // New customer: one call (1 credit) returns everything they shared.
    const shared = (await contashare.sharedData(tokens.access_token)) ?? {};
    const email = (shared.emails ?? []).find((e) => e.email_detail.is_verified) ?? shared.emails?.[0];
    if (!email) return res.status(422).send('Share an email address to sign up.');

    // Never sign someone in to, or link, an account that already has this email address.
    if (await users.findByEmail(email.email_detail.email_address)) return res.status(409).send('Log in with your password instead.');

    user = await users.create({ contashareId, email: email.email_detail.email_address });
  }

  // Keep both tokens: you need them to fetch updates when a webhook arrives.
  await users.saveTokens(user, tokens.access_token, tokens.refresh_token);
  req.session.regenerate(() => { req.session.userId = user.id; res.redirect('/dashboard'); });
});
```

- `me()` is free. The ID never changes, it is the same for every OAuth client your team owns, and another company gets a
  different one for the same person.
- `sharedData()` returns `null` when there is nothing new since you last called it. Use `get('/api/v1/email', token)` and the
  other list endpoints after that.
- `authorizeUrl({ state, reconfirm: true })` shows the consent screen again, so the customer can share something new.
- Tokens last a year. Call `refresh(refreshToken)` well before then and store the new pair straight away.
- An error answer throws a `ContaShareError` with `status` and `body`.
- A customer's token is only ever sent to ContaShare: `get()` refuses a full URL on any other site, and redirects are not
  followed. Still check a webhook's signature before you act on it.

## Webhooks

ContaShare signs every webhook with a `Signature` header. Check it against the **raw** body:

```js
import express from 'express';
import { verifyWebhookSignature } from 'contashare';

app.post('/webhooks/contashare', express.raw({ type: 'application/json' }), (req, res) => {
  if (!verifyWebhookSignature(req.body, req.get('Signature'), process.env.CONTASHARE_WEBHOOK_SECRET)) {
    return res.sendStatus(401);
  }

  const { resource_url: resourceUrl, action } = JSON.parse(req.body);
  // Queue a job that calls contashare.get(resourceUrl, thatCustomersToken) for an update.
  res.sendStatus(204);
});
```

The [OAuth guide](https://contashare.com/help/oauth) and [webhooks guide](https://contashare.com/help/webhooks) cover the rest,
and every endpoint is in the [API reference](https://contashare.com/docs/api).

## Testing

```bash
npm test
```

## Licence

MIT. See [LICENSE](LICENSE).
