# COCONUT

COCONUT is protected by a two-step authentication gate when deployed with Cloudflare Pages Functions.

## Required deployment variables

Configure these encrypted environment variables in the Cloudflare Pages project before deploying:

| Variable | Purpose |
| --- | --- |
| `AUTH_USERNAME` | First-step username |
| `AUTH_PASSWORD` | First-step password |
| `AUTH_ACCESS_CODE` | Separate second-step access code |
| `AUTH_SESSION_SECRET` | Long, random secret used to sign authentication cookies |

Use `.dev.vars.example` as the template for local Cloudflare development. Do not commit a populated `.dev.vars` file.

The authentication function protects every request, including direct game URLs and static game assets. A successful session is stored in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie for eight hours. The first verification step expires after five minutes.
