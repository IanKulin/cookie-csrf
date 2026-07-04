// test runner is Node's built-in
// https://nodejs.org/api/test.html
// `npm test` to run

import { test, describe } from "node:test";
import assert from "node:assert";
import cookieCsrfProtection from "../cookie-csrf.js";

// Mock objects for testing.
// Note: deliberately NO `session` — cookie-csrf must never touch req.session.
function createMockReq(overrides = {}) {
  return {
    method: "GET",
    cookies: {},
    body: {},
    query: {},
    headers: {},
    ...overrides,
  };
}

function createMockRes() {
  const res = {
    cookies: {},
    cookie: function (name, value, options) {
      this.cookies[name] = { value, options };
    },
  };
  return res;
}

function createMockNext() {
  const calls = [];
  function next(error) {
    calls.push(error || "called");
  }
  next.calls = calls;
  return next;
}

describe("cookieCsrfProtection", () => {
  const testSecret = "this-is-a-very-long-secret-key-for-testing-purposes";

  test("should return a function", () => {
    assert.equal(typeof cookieCsrfProtection, "function");
  });

  describe("initialization", () => {
    test("should throw error if secret is too short", () => {
      assert.throws(() => {
        cookieCsrfProtection({ secret: "short" });
      }, /CSRF secret must be at least 32 characters long/);
    });

    test("should throw error if no secret provided", () => {
      assert.throws(() => {
        cookieCsrfProtection({});
      }, /CSRF secret must be at least 32 characters long/);
    });

    test("should accept valid configuration", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      assert.equal(typeof middleware, "function");
    });
  });

  describe("configuration options", () => {
    test("should use default cookie settings", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const cookieData = res.cookies.csrf_pre_token;
      assert.equal(cookieData.options.path, "/");
      assert.equal(cookieData.options.httpOnly, true);
      assert.equal(cookieData.options.sameSite, "strict");
      assert.equal(cookieData.options.secure, true);
      assert.equal(cookieData.options.maxAge, 3600000);
    });

    test("should use custom cookie settings", () => {
      const middleware = cookieCsrfProtection({
        secret: testSecret,
        cookie: {
          key: "custom_csrf",
          path: "/api",
          httpOnly: false,
          sameSite: "lax",
          secure: false,
          maxAge: 7200000,
        },
      });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const cookieData = res.cookies.custom_csrf;
      assert.equal(cookieData.options.path, "/api");
      assert.equal(cookieData.options.httpOnly, false);
      assert.equal(cookieData.options.sameSite, "lax");
      assert.equal(cookieData.options.secure, false);
      assert.equal(cookieData.options.maxAge, 7200000);
    });

    test("should use custom ignore methods", () => {
      const middleware = cookieCsrfProtection({
        secret: testSecret,
        ignoreMethods: ["GET", "POST"],
      });
      const req = createMockReq({ method: "POST" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.preCsrfToken, "function");
    });

    test("should accept valid token from custom parameter name", () => {
      const middleware = cookieCsrfProtection({
        secret: testSecret,
        csrfParam: "custom_token",
      });

      // First generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Then validate it using the custom parameter name
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        body: { custom_token: validToken },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      middleware(postReq, postRes, postNext);

      assert.equal(postNext.calls.length, 1);
      assert.equal(postNext.calls[0], "called");
    });

    test("should reject invalid tokens regardless of parameter name", () => {
      const middleware = cookieCsrfProtection({
        secret: testSecret,
        csrfParam: "custom_token",
      });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "invalid.token" },
        body: { custom_token: "invalid.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should ignore token in default _csrf_pre field when using custom parameter", () => {
      const middleware = cookieCsrfProtection({
        secret: testSecret,
        csrfParam: "custom_token",
      });

      // Generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Put valid token in default field, but leave custom field empty
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        body: {
          _csrf_pre: validToken, // Valid token in default location
          custom_token: undefined, // No token in configured location
        },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      middleware(postReq, postRes, postNext);

      // Should fail because it didn't find token in custom_token field
      assert.equal(postNext.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("HTTP method handling", () => {
    test("should generate token for GET requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "GET" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.preCsrfToken, "function");
      assert.ok(res.cookies.csrf_pre_token);
      assert.ok(res.cookies.csrf_pre_token.value);
    });

    test("should generate token for HEAD requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "HEAD" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.preCsrfToken, "function");
    });

    test("should generate token for OPTIONS requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "OPTIONS" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0], "called");
      assert.equal(typeof req.preCsrfToken, "function");
    });

    test("should validate token for POST requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "invalid.token" },
        body: { _csrf_pre: "invalid.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls.length, 1);
      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      assert.equal(next.calls[0].status, 403);
    });

    test("should handle PUT requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      // First, generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Then, test PUT request with valid token
      const putReq = createMockReq({
        method: "PUT",
        cookies: { csrf_pre_token: validToken },
        body: { _csrf_pre: validToken },
      });
      const putRes = createMockRes();
      const putNext = createMockNext();

      middleware(putReq, putRes, putNext);

      assert.equal(putNext.calls.length, 1);
      assert.equal(putNext.calls[0], "called");
      assert.equal(typeof putReq.preCsrfToken, "function");
    });

    test("should handle PATCH requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      // First, generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Then, test PATCH request with valid token
      const patchReq = createMockReq({
        method: "PATCH",
        cookies: { csrf_pre_token: validToken },
        body: { _csrf_pre: validToken },
      });
      const patchRes = createMockRes();
      const patchNext = createMockNext();

      middleware(patchReq, patchRes, patchNext);

      assert.equal(patchNext.calls.length, 1);
      assert.equal(patchNext.calls[0], "called");
      assert.equal(typeof patchReq.preCsrfToken, "function");
    });

    test("should handle DELETE requests", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      // First, generate a valid token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Then, test DELETE request with valid token
      const deleteReq = createMockReq({
        method: "DELETE",
        cookies: { csrf_pre_token: validToken },
        headers: { "x-pre-csrf-token": validToken }, // Using header for variety
      });
      const deleteRes = createMockRes();
      const deleteNext = createMockNext();

      middleware(deleteReq, deleteRes, deleteNext);

      assert.equal(deleteNext.calls.length, 1);
      assert.equal(deleteNext.calls[0], "called");
      assert.equal(typeof deleteReq.preCsrfToken, "function");
    });
  });

  describe("token rotation on verified requests (lazy)", () => {
    // helper: run a GET to mint a valid token, then a verified POST
    function verifiedPost(middleware, overrides = {}) {
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      middleware(getReq, getRes, createMockNext());
      const validToken = getRes.cookies.csrf_pre_token.value;

      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        body: { _csrf_pre: validToken },
        ...overrides,
      });
      const postRes = createMockRes();
      const postNext = createMockNext();
      middleware(postReq, postRes, postNext);
      return { postReq, postRes, postNext, validToken };
    }

    test("does NOT set a cookie on a verified POST that never calls preCsrfToken() (no moot cookie)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const { postRes, postNext } = verifiedPost(middleware);

      assert.equal(postNext.calls[0], "called");
      // handler redirected without asking for a token → nothing rotated
      assert.equal(postRes.cookies.csrf_pre_token, undefined);
    });

    test("calling preCsrfToken() rotates: sets a new cookie whose value equals the returned token", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const { postReq, postRes, validToken } = verifiedPost(middleware);

      const exposed = postReq.preCsrfToken();
      assert.ok(postRes.cookies.csrf_pre_token, "a fresh cookie is set");
      assert.equal(postRes.cookies.csrf_pre_token.value, exposed);
      // it is genuinely rotated, not the just-submitted token
      assert.notEqual(exposed, validToken);
    });

    test("the rotated token verifies on a subsequent POST (bad-password re-render regression)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const { postReq, postRes } = verifiedPost(middleware);

      // handler re-renders a form with the rotated token
      const rotatedToken = postReq.preCsrfToken();
      const rotatedCookie = postRes.cookies.csrf_pre_token.value;

      // the user submits that re-rendered form
      const nextReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: rotatedCookie },
        body: { _csrf_pre: rotatedToken },
      });
      const nextRes = createMockRes();
      const nextNext = createMockNext();
      middleware(nextReq, nextRes, nextNext);

      assert.equal(nextNext.calls[0], "called");
    });

    test("preCsrfToken() is memoised within a request (stable across repeated calls)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const { postReq } = verifiedPost(middleware);

      assert.equal(postReq.preCsrfToken(), postReq.preCsrfToken());
    });

    test("a missing/invalid token still throws EBADCSRFTOKEN and does not rotate", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "invalid.token" },
        body: { _csrf_pre: "invalid.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      assert.equal(res.cookies.csrf_pre_token, undefined);
    });
  });

  describe("no-session contract", () => {
    test("should generate a token when req.session is undefined (safe method)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "GET" }); // no session key at all
      const res = createMockRes();
      const next = createMockNext();

      // must not throw "Session middleware required"
      assert.doesNotThrow(() => middleware(req, res, next));
      assert.equal(next.calls[0], "called");
      assert.ok(res.cookies.csrf_pre_token.value);
      assert.equal(req.session, undefined); // untouched
    });

    test("should validate a token when req.session is null (unsafe method)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq({ method: "GET", session: null });
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      const postReq = createMockReq({
        method: "POST",
        session: null,
        cookies: { csrf_pre_token: validToken },
        body: { _csrf_pre: validToken },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      assert.doesNotThrow(() => middleware(postReq, postRes, postNext));
      assert.equal(postNext.calls[0], "called");
    });

    test("should set req.preCsrfToken and NOT set req.csrfToken (no collision)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({ method: "GET" });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(typeof req.preCsrfToken, "function");
      assert.equal(req.csrfToken, undefined);
    });
  });

  describe("token generation and validation", () => {
    test("should generate valid token structure", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq();
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      const token = res.cookies.csrf_pre_token.value;
      const parts = token.split(".");
      assert.equal(parts.length, 2);
      assert.ok(parts[0].length > 0); // HMAC
      assert.ok(parts[1].length > 0); // Random value
    });

    test("should generate a different token on each safe request (per-request nonce)", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const req1 = createMockReq();
      const req2 = createMockReq();
      const res1 = createMockRes();
      const res2 = createMockRes();
      const next = createMockNext();

      middleware(req1, res1, next);
      middleware(req2, res2, next);

      assert.notEqual(
        res1.cookies.csrf_pre_token.value,
        res2.cookies.csrf_pre_token.value,
      );
    });

    test("should validate matching tokens", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      // First, generate a token
      const getReq = createMockReq({ method: "GET" });
      const getRes = createMockRes();
      const getNext = createMockNext();

      middleware(getReq, getRes, getNext);
      const generatedToken = getRes.cookies.csrf_pre_token.value;

      // Then, validate it
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: generatedToken },
        body: { _csrf_pre: generatedToken },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();

      middleware(postReq, postRes, postNext);

      assert.equal(postNext.calls.length, 1);
      assert.equal(postNext.calls[0], "called");
    });

    test("should reject mismatched tokens", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "cookie.token" },
        body: { _csrf_pre: "different.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("cross-instance verification (no per-user binding)", () => {
    test("token from one instance verifies against another with the SAME secret", () => {
      const instanceA = cookieCsrfProtection({ secret: testSecret });
      const instanceB = cookieCsrfProtection({ secret: testSecret });

      // Mint with instance A
      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      instanceA(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      // Verify with instance B
      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        body: { _csrf_pre: token },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();
      instanceB(postReq, postRes, postNext);

      assert.equal(postNext.calls[0], "called");
    });

    test("token FAILS against an instance with a DIFFERENT secret", () => {
      const instanceA = cookieCsrfProtection({ secret: testSecret });
      const instanceB = cookieCsrfProtection({
        secret: "different-secret-key-for-testing-purposes",
      });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      instanceA(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      const postReq = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        body: { _csrf_pre: token },
      });
      const postRes = createMockRes();
      const postNext = createMockNext();
      instanceB(postReq, postRes, postNext);

      assert.equal(postNext.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("error conditions", () => {
    test("should fail when cookie token is missing", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        body: { _csrf_pre: "some.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail when request token is missing", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "some.token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail with malformed cookie token", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "malformed-token" },
        body: { _csrf_pre: "malformed-token" },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should fail with empty token parts", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: "." },
        body: { _csrf_pre: "." },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("token sources", () => {
    test("should accept token from request body", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        body: { _csrf_pre: token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should reject tokens from query string for security", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      // Token only in query string — must be ignored
      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        query: { _csrf_pre: token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);

      assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should accept token from x-pre-csrf-token header", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        headers: { "x-pre-csrf-token": token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should accept token from x-xsrf-pre-token header", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const token = getRes.cookies.csrf_pre_token.value;

      const req = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        headers: { "x-xsrf-pre-token": token },
      });
      const res = createMockRes();
      const next = createMockNext();

      middleware(req, res, next);
      assert.equal(next.calls[0], "called");
    });

    test("should handle token precedence correctly", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });
      // documents the current behaviour: body > x-pre-csrf-token > x-xsrf-pre-token

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      // Test 1: Body token should take precedence over header
      const req1 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        body: { _csrf_pre: validToken },
        headers: { "x-pre-csrf-token": "invalid-token" },
      });
      const res1 = createMockRes();
      const next1 = createMockNext();

      middleware(req1, res1, next1);
      assert.equal(next1.calls[0], "called");

      // Test 2: x-pre-csrf-token should take precedence over x-xsrf-pre-token
      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        headers: {
          "x-pre-csrf-token": validToken,
          "x-xsrf-pre-token": "invalid-token",
        },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware(req2, res2, next2);
      assert.equal(next2.calls[0], "called");

      // Test 3: Should fall back to x-xsrf-pre-token when others missing
      const req3 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: validToken },
        headers: {
          "x-xsrf-pre-token": validToken,
        },
      });
      const res3 = createMockRes();
      const next3 = createMockNext();

      middleware(req3, res3, next3);
      assert.equal(next3.calls[0], "called");
    });
  });

  describe("constant time comparison", () => {
    // We can't directly test the constantTimeEquals function since it's not exported,
    // but we can test its behavior through the middleware

    test("should not be vulnerable to timing attacks on token comparison", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const validToken = getRes.cookies.csrf_pre_token.value;

      const testTokens = [
        "a",
        "ab",
        "abc",
        validToken.slice(0, -1), // One character short
        validToken + "x", // One character long
        "x".repeat(validToken.length), // Same length, all wrong
      ];

      testTokens.forEach((testToken) => {
        const req = createMockReq({
          method: "POST",
          cookies: { csrf_pre_token: validToken },
          body: { _csrf_pre: testToken },
        });
        const res = createMockRes();
        const next = createMockNext();

        middleware(req, res, next);
        assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      });
    });
  });

  describe("Misc edge cases", () => {
    test("should work with very long tokens", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const getReq = createMockReq();
      const getRes = createMockRes();
      const getNext = createMockNext();
      middleware(getReq, getRes, getNext);
      const normalToken = getRes.cookies.csrf_pre_token.value;

      // Test 1: Normal token should work
      const req1 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: normalToken },
        body: { _csrf_pre: normalToken },
      });
      const res1 = createMockRes();
      const next1 = createMockNext();

      middleware(req1, res1, next1);
      assert.equal(next1.calls[0], "called");

      // Test 2: Extremely long invalid token should fail gracefully
      const veryLongToken = "a".repeat(500); // Much longer than MAX_TOKEN_LENGTH (256)
      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: veryLongToken },
        body: { _csrf_pre: veryLongToken },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware(req2, res2, next2);
      assert.equal(next2.calls[0].code, "EBADCSRFTOKEN");

      // Test 3: Token at exactly MAX_TOKEN_LENGTH should be handled
      const maxLengthToken = "b".repeat(256); // Exactly MAX_TOKEN_LENGTH
      const req3 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: maxLengthToken },
        body: { _csrf_pre: maxLengthToken },
      });
      const res3 = createMockRes();
      const next3 = createMockNext();

      middleware(req3, res3, next3);
      assert.equal(next3.calls[0].code, "EBADCSRFTOKEN");
    });
  });

  describe("HMAC verification edge cases", () => {
    test("should fail with token generated using different secret", () => {
      const middleware1 = cookieCsrfProtection({ secret: testSecret });
      const middleware2 = cookieCsrfProtection({
        secret: "different-secret-key-for-testing-purposes",
      });

      const req1 = createMockReq();
      const res1 = createMockRes();
      const next1 = createMockNext();
      middleware1(req1, res1, next1);
      const token = res1.cookies.csrf_pre_token.value;

      const req2 = createMockReq({
        method: "POST",
        cookies: { csrf_pre_token: token },
        body: { _csrf_pre: token },
      });
      const res2 = createMockRes();
      const next2 = createMockNext();

      middleware2(req2, res2, next2);
      assert.equal(next2.calls[0].code, "EBADCSRFTOKEN");
    });

    test("should handle null/undefined values gracefully", () => {
      const middleware = cookieCsrfProtection({ secret: testSecret });

      const testCases = [
        { cookies: { csrf_pre_token: null }, body: { _csrf_pre: null } },
        {
          cookies: { csrf_pre_token: undefined },
          body: { _csrf_pre: undefined },
        },
        { cookies: { csrf_pre_token: "" }, body: { _csrf_pre: "" } },
      ];

      testCases.forEach((testCase) => {
        const req = createMockReq({
          method: "POST",
          ...testCase,
        });
        const res = createMockRes();
        const next = createMockNext();

        middleware(req, res, next);
        assert.equal(next.calls[0].code, "EBADCSRFTOKEN");
      });
    });
  });
});
