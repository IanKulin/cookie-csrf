import type { RequestHandler, Request } from "express";

declare module "express-serve-static-core" {
  interface Request {
    preCsrfToken(): string;
  }
}

export interface CookieCsrfCookieOptions {
  key?: string;
  path?: string;
  httpOnly?: boolean;
  sameSite?: "strict" | "lax" | "none" | boolean;
  secure?: boolean;
  maxAge?: number | null;
}

export interface CookieCsrfOptions {
  secret: string;
  cookie?: CookieCsrfCookieOptions;
  ignoreMethods?: string[];
  value?: (req: Request) => string | undefined;
  csrfParam?: string;
}

declare function cookieCsrfProtection(
  options: CookieCsrfOptions,
): RequestHandler;

export default cookieCsrfProtection;
