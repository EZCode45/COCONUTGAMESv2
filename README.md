# COCONUT

COCONUT includes a local testing account server. It stores accounts, player data, approved devices, administrator notifications, and sessions in `data/accounts.json`.

## Run locally

```sh
node server.js
```

Open `http://localhost:8787`, create the first administrator account, and use the administrator dashboard to create player accounts. A player signing in from a new browser device must request a temporary code. The code appears in the administrator notification panel and expires after 15 minutes.

Player data belongs to the account in `data/accounts.json`, not the browser. Players can save and reset their own data and change their password. Administrators can reset a player's data, approved devices, or password.

This is a local testing server. Do not expose it to the internet or use it for sensitive accounts.
