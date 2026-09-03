# Reservations Academy — with reviewer logins

Training module + login system + feedback collector, in one small Node app.

* Reviewers sign in with a username and password. Passwords are bcrypt-hashed;
  the server never stores or sends the plain text.
* A reviewer can only ever read their **own** comments — enforced in the SQL
  query, not in the browser.
* The owner account sees every comment and manages reviewers at `/admin`.
* Comments are also mirrored to the existing Google Sheet, so the triage
  workflow and screenshot links keep working.

## Deploying to Railway

1. Put these files in a GitHub repo (root level, no folders):
   `package.json`, `server.js`, `academy.html`, `.gitignore`
2. Railway → **New Project** → **Deploy from GitHub repo** → pick it.
3. In the project, **+ New** → **Database** → **Add PostgreSQL**.
   Railway sets `DATABASE_URL` automatically.
4. On the app service, open **Variables** and add:

   | Variable | Value |
   |---|---|
   | `SESSION_SECRET` | any long random string |
   | `ADMIN_USER` | `amar` |
   | `ADMIN_PASS` | the password you want for your own first sign-in |
   | `NODE_ENV` | `production` |
   | `SHEET_ENDPOINT` | your Apps Script `/exec` URL (optional — mirrors to the Sheet) |

5. **Settings → Networking → Generate Domain** to get the public URL.

Open the URL, sign in as `ADMIN_USER`, and you are asked to set your own
password. Then go to `/admin` to add reviewers.

## Adding reviewers

`/admin` → type a username and full name → **Add reviewer**. The page shows a
one-time starting password. Send the person their username and that password;
they are required to choose their own on first sign-in, and the starting one
stops working immediately.

**Reset password** issues a new starting password. **Disable** blocks sign-in
without deleting their comments.

## Local development

```bash
npm install
export DATABASE_URL=postgresql://user@localhost:5432/academy
export ADMIN_USER=amar ADMIN_PASS=choose-something SESSION_SECRET=dev
npm start          # http://localhost:3000
```

## Notes

* If `ADMIN_PASS` is not set, a random owner password is printed once in the
  Railway deploy logs.
* `academy.html` is the training module. To publish new content, rebuild it and
  replace this file — nothing else changes.
