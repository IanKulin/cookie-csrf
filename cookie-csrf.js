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
      // for the methods we don't need to check, we mint a fresh token, put it in
      // a cookie, and expose an accessor so the library user can embed it in html.
      // Deliberately does NOT touch req.session — that is the whole point.
      const tokenData = generateToken(config);
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
    // for the rare situation where the library user needs to render another form
    // with a POST action and wants a fresh token, provide that ability
    req.preCsrfToken = () => generateToken(config).token;
    next();
  };
}

function generateToken(config) {
  // a fresh random nonce per safe request — there is no session to key from,
  // so there is nothing to make the token stable across requests (see the
  // multi-tab caveat in the README)
  const randomValue = crypto.randomBytes(32).toString("hex");
  const message = `${randomValue.length}!${randomValue}`; // no sessionID segment
  const hmac = crypto
    .createHmac("sha256", config.secret)
    .update(message)
    .digest("hex");
  const token = `${hmac}.${randomValue}`;
  const cookieOptions = {
    path: config.cookie.path,
    httpOnly: config.cookie.httpOnly,
    sameSite: config.cookie.sameSite,
    secure: config.cookie.secure,
    maxAge: config.cookie.maxAge,
  };
  return {
    token,
    cookieOptions,
  };
}

function verifyToken(req, config) {
  const cookieToken = req.cookies[config.cookie.key];
  const requestToken = config.value(req);
  if (!cookieToken || !requestToken) {
    return false;
  }
  const cookieParts = cookieToken.split(".");
  if (cookieParts.length !== 2) {
    return false;
  }
  const hmacFromCookie = cookieParts[0];
  const randomValue = cookieParts[1];
  if (!randomValue) {
    return false; // rejects "malformed", "."
  }
  // recreate the HMAC from the random value alone (no session segment)
  const message = `${randomValue.length}!${randomValue}`;
  const expectedHmac = crypto
    .createHmac("sha256", config.secret)
    .update(message)
    .digest("hex");
  // compare them
  return (
    constantTimeEquals(hmacFromCookie, expectedHmac) &&
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
