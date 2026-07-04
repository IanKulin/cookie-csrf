import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
// The intended real-world combo:
//   cookie-csrf  → pre-auth login flow (no session needed)
//   small-csrf   → authenticated area (token bound to the persisted session)
import cookieCsrfProtection from "../cookie-csrf.js";
import csrfProtection from "small-csrf";

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.set("views", "./views");

app.use(cookieParser("your-cookie-secret"));

app.use(
  session({
    // using memoryStore
    secret: "your-secret-key",
    resave: false,
    // No session row is created for anonymous visitors. cookie-csrf makes this
    // safe on /login — it never touches req.session, so GET /login sends no
    // connect.sid and writes nothing to the store.
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    },
  }),
);

// form parsing
app.use(express.urlencoded({ extended: true }));

// Pre-auth CSRF: stateless signed nonce cookie. Applied at ROUTE level (only on
// /login), never globally, and never dirties the session.
const cookieCsrf = cookieCsrfProtection({
  secret: "cookieCsrfSecret32CharsForHMACuse", // 32-char secret for HMAC
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  },
});

// Authenticated-area CSRF: bound to the now-persisted session via small-csrf.
const sessionCsrf = csrfProtection({
  secret: "sessionCsrfSecret32CharsForHMAC!!", // a DIFFERENT secret from the pre-auth one
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  },
  perSessionTokens: true,
});

// Flash-message middleware only. Deliberately does NOT issue a CSRF token and
// deliberately does NOT modify the session (reading + deleting absent keys is a
// no-op), so anonymous requests still create no session row.
app.use((req, res, next) => {
  res.locals.errorMessage = req.session.errorMessage;
  res.locals.successMessage = req.session.successMessage;
  delete req.session.errorMessage;
  delete req.session.successMessage;
  next();
});

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  } else {
    req.session.errorMessage = "Please log in to access this page.";
    req.session.save(() => {
      res.redirect("/login");
    });
  }
}

app.get("/", (req, res) => {
  res.redirect("/login");
});

// --- Pre-auth login flow: cookie-csrf only -------------------------------

app.get("/login", cookieCsrf, (req, res) => {
  // No connect.sid is sent here: neither cookieCsrf nor the flash middleware
  // touches the session. Only the csrf_pre_token cookie is set.
  res.render("login", { preCsrfToken: req.preCsrfToken() });
});

app.post("/login", cookieCsrf, (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  if (username === "admin" && password === "password") {
    // Authenticated — now rotate away from the weaker pre-auth token:
    //   1. retire the pre-auth cookie, and
    //   2. hand off to small-csrf, whose token is issued on the next
    //      authenticated GET (GET /dashboard below).
    res.clearCookie("csrf_pre_token");
    req.session.user = { username: username };
    req.session.successMessage = "Login successful!";
    req.session.save(() => {
      res.redirect("/dashboard");
    });
  } else {
    req.session.errorMessage = "Invalid username or password.";
    req.session.save(() => {
      res.redirect("/login");
    });
  }
});

// --- Authenticated area: small-csrf (session-bound) ----------------------

app.get("/dashboard", requireAuth, sessionCsrf, (req, res) => {
  res.render("dashboard", { csrfToken: req.csrfToken() });
});

app.post("/dashboard/action", requireAuth, sessionCsrf, (req, res) => {
  req.session.successMessage = "Action performed successfully!";
  req.session.save(() => {
    res.redirect("/dashboard");
  });
});

app.get("/logout", (req, res) => {
  if (req.session.user) {
    delete req.session.user;
    req.session.successMessage = "Logout successful!";
  }
  req.session.save(() => {
    res.redirect("/login");
  });
});

// Shared error handler — one code (EBADCSRFTOKEN) is raised by BOTH middlewares.
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    // handle CSRF errors from either middleware
    console.log(`Possible CSRF attack from ${req.ip} on route ${req.url}`);
    req.session.errorMessage =
      "Invalid or expired form submission, please try again";
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("Session save error:", saveErr);
      }
      res.redirect("/login");
    });
  } else {
    // other errors
    req.session.errorMessage = "Something went wrong";
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error("Session save error:", saveErr);
      }
      res.status(err.status || 500).redirect("/");
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
