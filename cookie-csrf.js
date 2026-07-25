import crypto from "crypto";

/**
 * Pre-session CSRF protection middleware implementing OWASP's Signed
 * Double-Submit Cookie pattern, but WITHOUT binding the token to a session.
 *
 * The token is bound only to a self-minted, HMAC-signed nonce cookie, so the
 * middleware performs zero session reads/writes. This makes it suitable for
 * UNAUTHENTICATED routes (typically the login form) where dirtying the session
 * on every GET would defeat `saveUninitialized: false`.
 *
 * It is WEAKER than session-bound CSRF (see small-csrf): the HMAC
 * only defends against cookie injection, not user impersonation. Use it only on
 * pre-auth routes and rotate to a session-bound token once the user logs in.
 */
function cookieCsrfProtection(options = {}) {
  if (!options.secret || options.secret.length < 32) {
    throw new Error("CSRF secret must be at least 32 characters long");
  }
  const config = {
    secret: options.secret,
    cookie: {
      key: options.cookie?.key || "csrf_pre_token",
      path: options.cookie?.path || "/",
      httpOnly: options.cookie?.httpOnly !== false,
      sameSite: options.cookie?.sameSite || "strict",
      secure: options.cookie?.secure !== false,
      maxAge: options.cookie?.maxAge || 3600000, // 1 hour in milliseconds, null would be a session cookie
    },
    ignoreMethods: options.ignoreMethods || ["GET", "HEAD", "OPTIONS"],
    csrfParam: options.csrfParam || "_csrf_pre", // what name is used for the token
  };
  // where to find the token — a closure so defaultValue can read config.csrfParam
  config.value = options.value || ((req) => defaultValue(req, config));
  // return the middleware function
  return function cookieCsrf(req, res, next) {
    if (config.ignoreMethods.includes(req.method)) {
      // Reuse an existing, well-formed token/cookie instead of always minting
      // a fresh one. Without this, browsers that issue extra, invisible GETs
      // to a page a user is about to (or might) visit — Chromium's
      // prefetch/prerender, "View Source", a retried connection, a second
      // tab — silently rotate the cookie out from under a page that's
      // already been rendered and handed to the user, orphaning its
      // embedded token and 403ing the next real submit.
      //
      // isWellFormed only checks *shape* (HMAC matches the random value) —
      // it is not a security check on its own. A forged cookie that happens
      // to be well-formed but wrong is still caught where it matters:
      // verifyToken() on the POST re-derives the HMAC and rejects it.
      // Reusing it here on a GET costs nothing, since GETs are never
      // state-changing. Note the cookie's maxAge is refreshed on every
      // reuse, so an idle-but-open tab keeps its token alive on a sliding
      // window rather than a hard expiry from first mint (see README).
      const existingCookie = req.cookies?.[config.cookie.key];
      const tokenData = isWellFormed(existingCookie, config)
        ? { token: existingCookie, cookieOptions: buildCookieOptions(config) }
        : generateToken(config);
      res.cookie(config.cookie.key, tokenData.token, tokenData.cookieOptions);
      req.preCsrfToken = () => tokenData.token;
      next();
      return;
    }
    // for the methods we are checking, do the check
    if (!verifyToken(req, config)) {
      const csrfError = new Error("Invalid CSRF token");
      csrfError.code = "EBADCSRFTOKEN"; // same code as small-csrf so one handler catches both
      csrfError.status = 403; // HTTP status code
      return next(csrfError);
    }
    // Verification passed. Expose an accessor that ROTATES the token on demand:
    // the first time the handler asks for a token (e.g. re-rendering the login
    // form after a bad password) we mint a fresh nonce, refresh the cookie, and
    // return the matching token. This keeps the contract for preCsrfToken()
    // uniform with the safe-method branch — it always returns a token that
    // matches the cookie set on the response.
    //
    // Rotation is lazy: a handler that verifies and then redirects (e.g. a
    // SUCCESSFUL login) never calls the accessor, so no cookie is set and no
    // stale Set-Cookie is emitted. The token is minted once and memoised so
    // repeated calls within a request are stable.
    let rotated;
    req.preCsrfToken = () => {
      if (!rotated) {
        rotated = generateToken(config);
        res.cookie(config.cookie.key, rotated.token, rotated.cookieOptions);
      }
      return rotated.token;
    };
    next();
  };
}

function buildCookieOptions(config) {
  return {
    path: config.cookie.path,
    httpOnly: config.cookie.httpOnly,
    sameSite: config.cookie.sameSite,
    secure: config.cookie.secure,
    maxAge: config.cookie.maxAge,
  };
}

// HMAC over the random value alone (no session segment — there is no
// session to key from).
function computeHmac(config, randomValue) {
  const message = `${randomValue.length}!${randomValue}`;
  return crypto
    .createHmac("sha256", config.secret)
    .update(message)
    .digest("hex");
}

function generateToken(config) {
  const randomValue = crypto.randomBytes(32).toString("hex");
  const hmac = computeHmac(config, randomValue);
  const token = `${hmac}.${randomValue}`;
  return {
    token,
    cookieOptions: buildCookieOptions(config),
  };
}

// Checks *shape* only — that the HMAC matches the random value. This is not
// a security check on its own (see the safe-method branch above for why
// that's fine); it exists so the GET path can tell "a cookie this middleware
// minted" from "no cookie" or "garbage", without re-deriving the HMAC logic.
function isWellFormed(cookieValue, config) {
  if (!cookieValue) {
    return false;
  }
  const parts = cookieValue.split(".");
  if (parts.length !== 2 || !parts[1]) {
    return false; // rejects "malformed", "."
  }
  const [hmac, randomValue] = parts;
  return constantTimeEquals(hmac, computeHmac(config, randomValue));
}

function verifyToken(req, config) {
  const cookieToken = req.cookies[config.cookie.key];
  const requestToken = config.value(req);
  if (!cookieToken || !requestToken) {
    return false;
  }
  return (
    isWellFormed(cookieToken, config) &&
    constantTimeEquals(requestToken, cookieToken)
  );
}

function defaultValue(req, config) {
  return (
    (req.body && req.body[config.csrfParam]) ||
    req.headers["x-pre-csrf-token"] ||
    req.headers["x-xsrf-pre-token"]
  );
}

function constantTimeEquals(a, b) {
  const MAX_TOKEN_LENGTH = 256;
  const strA = String(a || "");
  const strB = String(b || "");
  // result is an accumulator for all the errors
  let result = strA.length ^ strB.length;
  for (let i = 0; i < MAX_TOKEN_LENGTH; i++) {
    const charA = i < strA.length ? strA.charCodeAt(i) : 0;
    const charB = i < strB.length ? strB.charCodeAt(i) : 0;
    result |= charA ^ charB;
  }
  return result === 0;
}

export default cookieCsrfProtection;
