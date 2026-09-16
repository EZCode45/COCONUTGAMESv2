# COCONUT

COCONUT includes an account system for Cloudflare Pages Functions. Visitors can create an account, sign in, and receive a secure eight-hour session before accessing the site.

## Required deployment configuration

Configure this encrypted environment variable in the Cloudflare Pages project before deploying:

| Variable | Purpose |
| --- | --- |
| `AUTH_SESSION_SECRET` | Long, random secret used to sign authentication cookies |

Create a D1 database and bind it to the Pages project as `ACCOUNTS`. Apply `migrations/0001_accounts.sql` to that database before deployment. For local development, bind the same name in your Cloudflare configuration and use `.dev.vars.example` as the template for local secrets. Do not commit a populated `.dev.vars` file.

The authentication function protects every request, including direct game URLs and static game assets. Passwords use PBKDF2-SHA-256 with unique random salts and are never stored in plaintext. Successful sessions are signed and stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookies for eight hours.
