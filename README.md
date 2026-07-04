# cookie-csrf ![NPM Version](https://img.shields.io/npm/v/cookie-csrf)

A lightweight, **stateless pre-session** CSRF protection middleware for Express, implementing OWASP's Signed Double-Submit Cookie pattern — but **without** binding the token to a session. Designed for **unauthenticated routes** (typically the login form).

## When to use this vs `small-csrf`

`cookie-csrf` is a companion to [`small-csrf`](https://github.com/IanKulin/small-csrf), not a replacement. Load both:

| Library       | Binds token to                    | Use on                                          |
| ------------- | --------------------------------- | ----------------------------------------------- |
| `small-csrf`  | `req.session.id`                  | Authenticated routes (the default)              |
| `cookie-csrf` | a self-minted signed cookie nonce | **Unauthenticated routes only** (e.g. `/login`) |

> **⚠️ Security caveat — read this first.**
> `cookie-csrf` is **weaker than session-bound CSRF**. Its HMAC signature only
> defends against cookie injection; it does **not** bind the token to a user
> identity. That is acceptable for the pre-auth case (whose real threat,
> login-CSRF, is stopped by the browser cookie jar + `SameSite`), but it means:
> **use it only on unauthenticated routes, and rotate to `small-csrf` the moment
> the user logs in.**

## Introduction

`cookie-csrf` implements the OWASP [Signed Double-Submit Cookie](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) pattern, but mints a **signed, stateless nonce cookie** instead of reading `req.session`. This means `GET /login` performs **zero session reads/writes and zero DB writes**.

Key features:

- No session dependency — safe to use with `saveUninitialized: false`
- Constant-time token comparison to prevent timing attacks
- Distinct request accessor, cookie key, param, and headers so it never collides with `small-csrf`
- Zero runtime dependencies, ESM, Node ≥ 20

Whilst any implementation errors are my own, credit goes to OWASP and their [CSRF Cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

## Installation

```bash
npm install cookie-csrf
```

## Quick Start

The intended setup runs **both** middlewares — `cookie-csrf` on the pre-auth login flow (route-level), `small-csrf` on the authenticated area:

```javascript
// npm install express express-session cookie-parser cookie-csrf small-csrf
import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import cookieCsrfProtection from "cookie-csrf";
import csrfProtection from "small-csrf";

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  session({
    secret: "your-session-secret",
    resave: false,
    saveUninitialized: false, // no session row for anonymous visitors
    cookie: { secure: process.env.NODE_ENV === "production" },
  }),
);

// Pre-auth CSRF (route-level, never global, never touches the session)
const cookieCsrf = cookieCsrfProtection({
  secret: "at-least-32-characters-long-pre-secret",
});

// Authenticated-area CSRF (session-bound)
const sessionCsrf = csrfProtection({
  secret: "a-different-32-plus-char-session-secret",
});

// --- Login flow: cookie-csrf, uses preCsrfToken() / _csrf_pre ---
app.get("/login", cookieCsrf, (req, res) => {
  res.send(`
    <form action="/login" method="POST">
      <input type="hidden" name="_csrf_pre" value="${req.preCsrfToken()}">
      <input name="username"><input type="password" name="password">
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/login", cookieCsrf, (req, res) => {
  // ...authenticate...
  res.clearCookie("csrf_pre_token"); // retire the pre-auth token
  req.session.user = { name: req.body.username }; // now a real session exists
  req.session.save(() => res.redirect("/dashboard"));
});

// --- Authenticated area: small-csrf, uses csrfToken() / _csrf ---
app.get("/dashboard", sessionCsrf, (req, res) => {
  res.send(`csrf token: ${req.csrfToken()}`);
});

// One handler catches CSRF errors from BOTH (same error code)
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token. Please try again.");
  }
  next(err);
});

app.listen(3000);
```

## Why not just use `small-csrf` on `/login`?

`small-csrf` binds each token to `req.session.id`. For that ID to be stable between `GET /login` (render) and `POST /login` (submit) under `saveUninitialized: false`, the app must dirty the session on the GET — the `req.session.initialized = true` workaround.

That write **defeats the point of `saveUninitialized: false`**: every unauthenticated visitor gets a persisted session row, so an attacker (or a crawler) can hammer `GET /login` and exhaust the session store / rate limits before anyone authenticates.

`cookie-csrf` removes the session dependency for the pre-auth route entirely, so `GET /login` creates no session and sends no `connect.sid`.

## Security model (and its limits)

- The barrier that actually stops CSRF is the browser cookie jar + `SameSite`: an attacker can't read the victim's HttpOnly cookie and can't plant one cross-site, so they can't put a matching token in a forged form.
- The HMAC signature only buys defence against **cookie injection** (a sibling subdomain / MITM writing a cookie value the attacker knows). It does **not** bind the token to a user identity.
- This is fine for the pre-auth case, whose real threat is login-CSRF (covered by the cookie-jar + `SameSite` barrier). It is **weaker than `small-csrf`** — so use it only on unauthenticated routes and rotate on login.

## Multi-tab caveat

Because there is no session to key from, a fresh random nonce is minted on **every** safe request. Opening the login form in two tabs therefore leaves only the **last** tab's cookie valid — submitting the older tab's form will 403 and the user simply reloads and retries. This is acceptable for a login form.

## How It Works

1. On a safe request (GET/HEAD/OPTIONS) a cryptographically strong random nonce is generated, HMAC-signed, and:
   - set as an HTTP-only cookie (`csrf_pre_token` by default), and
   - exposed via `req.preCsrfToken()` for inclusion in forms or AJAX.
2. On a state-changing request (POST/PUT/PATCH/DELETE) the middleware:
   - recomputes the HMAC from the cookie's random value and checks it (rejects cookie injection),
   - checks the submitted token equals the cookie token (double-submit),
   - both comparisons are constant-time.

## API Reference

### `cookieCsrfProtection(options)`

Creates and returns the CSRF middleware function.

#### Options

| Option            | Type     | Default                                                           | Description                                                         |
| ----------------- | -------- | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| `secret`          | String   | _required_                                                        | Secret key used for HMAC signature (must be at least 32 characters) |
| `cookie.key`      | String   | `"csrf_pre_token"`                                                | Name of the cookie storing the CSRF token                           |
| `cookie.path`     | String   | `"/"`                                                             | Path for the CSRF cookie                                            |
| `cookie.httpOnly` | Boolean  | `true`                                                            | Whether the cookie is HTTP only                                     |
| `cookie.sameSite` | String   | `"strict"`                                                        | SameSite policy for the cookie (`"strict"`, `"lax"`, or `"none"`)   |
| `cookie.secure`   | Boolean  | `true`                                                            | Whether the cookie requires HTTPS                                   |
| `cookie.maxAge`   | Number   | `3600000`                                                         | Max age of the cookie in milliseconds (1 hour default)              |
| `ignoreMethods`   | Array    | `["GET", "HEAD", "OPTIONS"]`                                      | HTTP methods that don't need CSRF validation                        |
| `csrfParam`       | String   | `"_csrf_pre"`                                                     | Name of the parameter containing the CSRF token in requests         |
| `value`           | Function | reads `body[csrfParam]` → `x-pre-csrf-token` → `x-xsrf-pre-token` | Custom extractor for the submitted token (never the query string)   |

### `req.preCsrfToken()`

Function added to the request object that returns the current pre-auth CSRF token. Use this to include the token in your login form or AJAX requests.

> **Note the deliberate renames vs `small-csrf`** so the two never collide when loaded together:
>
> | Surface          | small-csrf                     | cookie-csrf                                       |
> | ---------------- | ------------------------------ | ------------------------------------------------- |
> | Request accessor | `req.csrfToken()`              | `req.preCsrfToken()`                              |
> | Cookie key       | `csrf_token`                   | `csrf_pre_token`                                  |
> | Form param       | `_csrf`                        | `_csrf_pre`                                       |
> | Headers accepted | `x-csrf-token`, `x-xsrf-token` | `x-pre-csrf-token`, `x-xsrf-pre-token`            |
> | Error `code`     | `EBADCSRFTOKEN`                | `EBADCSRFTOKEN` (same — one handler catches both) |

## Security Considerations

For maximum security:

- Always use HTTPS in production environments
- Use a secret **different** from both your session secret and your `small-csrf` secret
- Use a cryptographically strong secret (at least 32 characters)
- **Rotate on login:** `res.clearCookie("csrf_pre_token")` and switch the authenticated area to `small-csrf`
- Set appropriate `sameSite` and `secure` cookie options for your application

## Tests

Uses the built-in Node test runner - available from Node 20
`npm test` to run

## Example App

To run a local demo of the `cookie-csrf` + `small-csrf` combo from a cloned repo:

```bash
cd example
npm install
npm start
```

Then visit http://localhost:3000. Observe that `GET /login` sets `csrf_pre_token` but **no** `connect.sid`; after login the pre-auth cookie is cleared and the dashboard is protected by `small-csrf`'s `csrf_token`.

## License

[MIT](LICENSE)

## Versions

- 0.1.0 - initial
