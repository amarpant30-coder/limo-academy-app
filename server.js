/**
 * Limo Anywhere Reservations Academy — reviewer logins + feedback collector.
 *
 * Everything is served from this one app: the training module, the login page,
 * the admin page, and the comments API. Passwords are bcrypt-hashed and never
 * leave the server; reviewers are identified by a signed session cookie, so a
 * reviewer can only ever read their own comments.
 */
const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

/* Railway terminates TLS in front of us; needed for secure cookies. */
app.set('trust proxy', 1);
app.use(express.json({ limit: '8mb' }));       // screenshots arrive as data URIs
app.use(express.urlencoded({ extended: false }));

/* ---------------------------------------------------------------- database */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      name       TEXT NOT NULL DEFAULT '',
      pass_hash  TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'reviewer',
      must_change BOOLEAN NOT NULL DEFAULT TRUE,
      disabled   BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS comments (
      id         TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      author     TEXT NOT NULL DEFAULT '',
      type       TEXT NOT NULL DEFAULT 'Suggestion',
      section    TEXT NOT NULL DEFAULT '',
      title      TEXT NOT NULL DEFAULT '',
      topic      TEXT NOT NULL DEFAULT '',
      body       TEXT NOT NULL DEFAULT '',
      shot_url   TEXT NOT NULL DEFAULT '',
      shot_data  TEXT NOT NULL DEFAULT '',
      mirrored   BOOLEAN NOT NULL DEFAULT FALSE,
      done       BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS comments_user_idx ON comments(user_id);
    CREATE TABLE IF NOT EXISTS issues (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username   TEXT NOT NULL DEFAULT '',
      kind       TEXT NOT NULL DEFAULT '',
      detail     TEXT NOT NULL DEFAULT '',
      comment_id TEXT NOT NULL DEFAULT '',
      resolved   BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS shot_data TEXT NOT NULL DEFAULT '';
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS mirrored  BOOLEAN NOT NULL DEFAULT FALSE;
  `);

  /* Owner account. If ADMIN_PASS is set it is applied on every boot, so the
     owner can always recover access by changing that variable in Railway.
     Remove ADMIN_PASS once you are in and the password is managed in-app. */
  const user = (process.env.ADMIN_USER || 'amar').toLowerCase().trim();
  const envPass = process.env.ADMIN_PASS;
  const { rows } = await pool.query(`SELECT count(*)::int AS n FROM users WHERE role='owner'`);

  if (rows[0].n === 0) {
    const pass = envPass || newPassword(10);
    await pool.query(
      `INSERT INTO users (username,name,pass_hash,role,must_change) VALUES ($1,$2,$3,'owner',$4)
       ON CONFLICT (username) DO NOTHING`,
      [user, 'Amar', bcrypt.hashSync(pass, 12), !envPass]);
    console.log('─'.repeat(58));
    console.log('  Owner account created — username: ' + user);
    if (!envPass) console.log('  one-time password: ' + pass + '   ← change it after signing in');
    else console.log('  password: the ADMIN_PASS you set in Railway variables');
    console.log('─'.repeat(58));
  } else if (envPass) {
    await pool.query(
      `UPDATE users SET pass_hash=$1, must_change=FALSE WHERE role='owner' AND username=$2`,
      [bcrypt.hashSync(envPass, 12), user]);
    console.log('Owner password set from ADMIN_PASS for "' + user + '".');
  } else {
    console.log('Owner account exists. Set ADMIN_PASS in Railway variables to reset its password.');
  }
}

/* ----------------------------------------------------------------- session */
const PgStore = require('connect-pg-simple')(session);
app.use(session({
  store: new PgStore({ pool, createTableIfMissing: true }),
  name: 'la.sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 30          // a month, so reviewers stay signed in
  }
}));

/* -------------------------------------------------------------- middleware */
/* A signed-in reviewer is re-checked against the users table, so that
   disabling or deleting someone ends their access straight away instead of
   waiting for their cookie to expire. The answer is cached briefly so this
   costs one small query per reviewer every 20 seconds, not one per request. */
const seatCache = new Map();                    // uid -> { until, ok, role, name }
function seatState(uid) {
  const hit = seatCache.get(uid);
  if (hit && hit.until > Date.now()) return Promise.resolve(hit);
  return pool.query('SELECT role, name, username, disabled FROM users WHERE id=$1', [uid])
    .then(({ rows }) => {
      const u = rows[0];
      const st = { until: Date.now() + 20000, ok: !!u && !u.disabled,
                   role: u ? u.role : null, name: u ? (u.name || u.username) : null };
      seatCache.set(uid, st);
      return st;
    })
    .catch(() => ({ until: 0, ok: true, role: null, name: null }));  // never lock people out on a DB blip
}
function forgetSeat(uid) { seatCache.delete(Number(uid)); }

function requireLogin(req, res, next) {
  if (!req.session.uid) {
    return req.path.startsWith('/api/')
      ? res.status(401).json({ ok: false, error: 'not signed in' })
      : res.redirect('/login');
  }
  seatState(req.session.uid).then(st => {
    if (!st.ok) {
      return req.session.destroy(() => {
        if (req.path.startsWith('/api/')) {
          res.status(401).json({ ok: false, error: 'this account is no longer active' });
        } else {
          res.redirect('/login?e=2');
        }
      });
    }
    if (st.role) req.session.role = st.role;    // a role change takes effect too
    if (st.name) req.session.name = st.name;
    next();
  });
}
function requireOwner(req, res, next) {
  if (req.session.role !== 'owner') return res.status(403).send('Not allowed');
  next();
}
/* Starting passwords are read off a screen and typed by hand, so leave out
   every character pair that looks alike in common fonts: 0/O, 1/l/I, 5/S, 2/Z. */
const PW_ALPHABET = 'ACDEFHJKLMNPQRTUVWXYZabcdefhijkmnprstuvwxyz347';
function newPassword(len) {
  const n = len || 10;
  let out = '';
  for (let i = 0; i < n; i++) {
    out += PW_ALPHABET[crypto.randomInt(0, PW_ALPHABET.length)];
    if (i === 3 || i === 7) out += '-';          // easier to read aloud
  }
  return out;
}

const esc = s => String(s == null ? '' : s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

/* ------------------------------------------------------------------- pages */
const ACADEMY = path.join(__dirname, 'academy.html');

app.get('/', requireLogin, (req, res) => {
  if (req.session.mustChange) return res.redirect('/password');
  res.sendFile(ACADEMY);
});

function shell(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#12151d;color:#1c2130;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px}
.card{background:#fff;border-radius:14px;padding:32px;width:100%;max-width:420px;box-shadow:0 18px 50px rgba(0,0,0,.35)}
.wide{max-width:860px}
h1{margin:0 0 6px;font-size:1.35rem}
p.sub{margin:0 0 22px;color:#6b7280;font-size:.92rem}
label{display:block;font-size:.85rem;font-weight:600;margin:14px 0 5px}
input{width:100%;padding:11px 12px;border:1px solid #d7dae1;border-radius:9px;font:inherit}
input:focus{outline:2px solid #e8532b;outline-offset:1px;border-color:#e8532b}
button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:9px;background:#e8532b;color:#fff;
  font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#d2461f}
.err{background:#fdecea;color:#a32b1c;padding:10px 12px;border-radius:8px;font-size:.9rem;margin-bottom:8px}
.ok{background:#e7f6ec;color:#1a7f42;padding:10px 12px;border-radius:8px;font-size:.9rem;margin-bottom:8px}
table{width:100%;border-collapse:collapse;margin-top:18px;font-size:.9rem}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid #eceef2}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.row>div{flex:1;min-width:150px}
.row button{width:auto;margin-top:0;padding:11px 18px}
.mini{padding:6px 10px;font-size:.82rem;width:auto;margin:0;background:#eceef2;color:#1c2130}
.mini:hover{background:#dfe2e8}
.mini.danger{background:#fdecea;color:#a32b1c}
.mini.danger:hover{background:#f9d9d5}
.inline{display:inline-flex;gap:5px;align-items:center;margin:0 6px 4px 0}
.inline input[type=text]{width:150px;padding:6px 9px;font-size:.85rem}
.check{display:flex;align-items:center;gap:8px;font-weight:400;font-size:.88rem;color:#4b5563;margin-top:12px}
.check input{width:auto}
.stat{background:#f3f4f7;border-radius:9px;padding:11px 14px;font-size:.9rem;margin:4px 0 18px;
  display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.stat .sp2{margin-left:auto;display:flex;gap:8px;align-items:center}
.issues{background:#fdf3e7;border:1px solid #f0d8b8;border-radius:9px;padding:12px 14px;margin:0 0 18px;font-size:.9rem}
.issues ul{margin:8px 0 0;padding-left:18px}
.issues li{margin-bottom:6px}
.issues .when{color:#8a6636;font-size:.82rem}
a.btn{display:inline-block;text-decoration:none;line-height:1.6}
code{user-select:all}
a{color:#e8532b}
code{background:#f3f4f7;padding:2px 6px;border-radius:5px;font-size:.88rem}
</style></head><body>${body}</body></html>`;
}

app.get('/login', (req, res) => {
  if (req.session.uid) return res.redirect('/');
  const bad = req.query.e === '2'
    ? '<div class="err">That account is no longer active. Ask Amar to set you up again.</div>'
    : req.query.e ? '<div class="err">That username or password was not right.</div>' : '';
  res.send(shell('Sign in — Reservations Academy', `<form class="card" method="post" action="/login">
    <h1>Reservations Academy</h1>
    <p class="sub">Sign in to review the training module.</p>
    ${bad}
    <label for="u">Username</label><input id="u" name="username" autocapitalize="none" autofocus required>
    <label for="p">Password</label><input id="p" name="password" type="password" required>
    <button type="submit">Sign in</button>
  </form>`));
});

app.post('/login', async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const u = rows[0];
    if (!u || u.disabled || !bcrypt.compareSync(password, u.pass_hash)) {
      return res.redirect('/login?e=1');
    }
    req.session.uid = u.id;
    req.session.role = u.role;
    req.session.name = u.name || u.username;
    req.session.mustChange = u.must_change;
    res.redirect(u.must_change ? '/password' : '/');
  } catch (err) {
    console.error(err);
    res.redirect('/login?e=1');
  }
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));
app.get('/logout',  (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/password', requireLogin, (req, res) => {
  const note = req.session.mustChange
    ? '<p class="sub">Choose your own password before you start.</p>'
    : '<p class="sub">Change your password.</p>';
  const bad = req.query.e ? '<div class="err">Passwords must match and be at least 8 characters.</div>' : '';
  res.send(shell('Set your password', `<form class="card" method="post" action="/password">
    <h1>Set your password</h1>${note}${bad}
    <label for="p1">New password</label><input id="p1" name="p1" type="password" required minlength="8" autofocus>
    <label for="p2">Repeat it</label><input id="p2" name="p2" type="password" required minlength="8">
    <button type="submit">Save and continue</button>
  </form>`));
});

app.post('/password', requireLogin, async (req, res) => {
  const { p1, p2 } = req.body;
  if (!p1 || p1.length < 8 || p1 !== p2) return res.redirect('/password?e=1');
  await pool.query('UPDATE users SET pass_hash=$1, must_change=FALSE WHERE id=$2',
    [bcrypt.hashSync(String(p1), 12), req.session.uid]);
  req.session.mustChange = false;
  res.redirect('/');
});

/* ------------------------------------------------------------------- admin */
app.get('/admin', requireLogin, requireOwner, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.id,u.username,u.name,u.role,u.disabled,u.must_change,
           (SELECT count(*)::int FROM comments c WHERE c.user_id=u.id) AS comments
    FROM users u ORDER BY u.role DESC, u.username`);

  /* Flash messages live in the session, so a password never lands in the
     address bar or browser history. */
  const flash = req.session.flash; delete req.session.flash;
  const stat = (await pool.query(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE mirrored)::int AS in_sheet,
            count(*) FILTER (WHERE NOT mirrored)::int AS pending FROM comments`)).rows[0];
  const issues = (await pool.query(
    `SELECT username,kind,detail,comment_id,created_at FROM issues
      WHERE resolved=FALSE ORDER BY created_at DESC LIMIT 20`)).rows;
  const note = flash
    ? `<div class="${flash.bad ? 'err' : 'ok'}">${flash.html}</div>`
    : '';

  const list = rows.map(u => {
    if (u.role === 'owner') {
      return `<tr><td><b>${esc(u.username)}</b> · owner</td><td>${esc(u.name)}</td>
        <td>${u.comments}</td><td>active</td>
        <td><a href="/password">change my password</a></td></tr>`;
    }
    return `<tr>
      <td><b>${esc(u.username)}</b>${u.disabled ? ' · disabled' : ''}</td>
      <td>${esc(u.name)}</td>
      <td>${u.comments}</td>
      <td>${u.must_change ? 'has not signed in yet' : 'active'}</td>
      <td>
        <form method="post" action="/admin/setpass/${u.id}" class="inline">
          <input type="text" name="password" placeholder="new password" autocomplete="off">
          <button class="mini">Set</button>
        </form>
        <form method="post" action="/admin/setpass/${u.id}" class="inline">
          <input type="hidden" name="generate" value="1">
          <button class="mini">Generate</button>
        </form>
        <form method="post" action="/admin/toggle/${u.id}" class="inline">
          <button class="mini">${u.disabled ? 'Enable' : 'Disable'}</button>
        </form>
        <form method="post" action="/admin/delete/${u.id}" class="inline"
              onsubmit="return confirm('Delete ${esc(u.username)} and their ${u.comments} comment(s) from this app? Rows already in the Google Sheet are not affected.')">
          <button class="mini danger">Delete</button>
        </form>
      </td></tr>`;
  }).join('');

  res.send(shell('Reviewers — Reservations Academy', `<div class="card wide">
    <h1>Reviewers</h1>
    <p class="sub">Give each person a username and a password you choose, then send them both.
      <a href="/">Open the module</a> · <a href="/logout">Sign out</a></p>
    <div class="stat">
      <b>${stat.total}</b> comment${stat.total === 1 ? '' : 's'} stored ·
      <b>${stat.in_sheet}</b> copied to the Google Sheet${stat.pending
        ? ` · <b style="color:#b4232c">${stat.pending} still to copy</b>` : ''}
      <span class="sp2">
        <a class="mini btn" href="/admin/export.json">Download a backup</a>
        <form method="post" action="/admin/retry-mirror" class="inline">
          <button class="mini">Retry Sheet copy</button></form>
      </span>
    </div>
    ${note}

    ${issues.length ? `<div class="issues">
      <b>&#9888; ${issues.length} problem${issues.length === 1 ? '' : 's'} reported by reviewers</b>
      <form method="post" action="/admin/issues/clear" class="inline" style="float:right">
        <button class="mini">Mark as looked at</button></form>
      <ul>${issues.map(i => `<li><b>${esc(i.username)}</b> — ${esc(i.kind)}
        ${i.comment_id ? `(comment <code>${esc(i.comment_id)}</code>)` : ''}
        <span class="when">${new Date(i.created_at).toLocaleString()}</span>
        ${i.detail ? `<br><span class="when">${esc(i.detail)}</span>` : ''}</li>`).join('')}</ul>
    </div>` : ''}

    <form method="post" action="/admin/create">
      <div class="row">
        <div><label for="nu">Username</label>
          <input id="nu" name="username" placeholder="priya" required autocapitalize="none" autocomplete="off"></div>
        <div><label for="nn">Full name</label>
          <input id="nn" name="name" placeholder="Priya Nair" autocomplete="off"></div>
        <div><label for="np">Password</label>
          <input id="np" name="password" placeholder="leave blank to generate one" autocomplete="off"></div>
        <button type="submit">Add reviewer</button>
      </div>
      <label class="check"><input type="checkbox" name="force" value="1">
        Make them choose their own password on first sign-in</label>
    </form>

    <table><thead><tr><th>Username</th><th>Name</th><th>Comments</th><th>Status</th><th>Password</th></tr></thead>
    <tbody>${list}</tbody></table>
    <p class="sub" style="margin-top:16px">Passwords must be at least 8 characters. Type one in the
      <b>Password</b> box and press <b>Set</b>, or press <b>Generate</b> for a random one.</p>
  </div>`));
});

app.post('/admin/create', requireLogin, requireOwner, async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 40);
  if (!username) { req.session.flash = { bad: true, html: 'Please give the reviewer a username.' }; return res.redirect('/admin'); }

  const typed = String(req.body.password || '').trim();
  if (typed && typed.length < 8) {
    req.session.flash = { bad: true, html: 'That password is too short — use at least 8 characters.' };
    return res.redirect('/admin');
  }
  const pw    = typed || newPassword(10);
  const force = typed ? !!req.body.force : true;   // generated ones must always be changed

  try {
    await pool.query(
      `INSERT INTO users (username,name,pass_hash,role,must_change) VALUES ($1,$2,$3,'reviewer',$4)`,
      [username, String(req.body.name || '').slice(0, 80), bcrypt.hashSync(pw, 12), force]);
    req.session.flash = { html: `Created <b>${esc(username)}</b> with password <code>${esc(pw)}</code>` +
      (force ? ' — they will choose their own on first sign-in.' : ' — send it to them.') };
  } catch (err) {
    req.session.flash = { bad: true, html: `Could not create <b>${esc(username)}</b> — that username may already exist.` };
  }
  res.redirect('/admin');
});

app.post('/admin/setpass/:id', requireLogin, requireOwner, async (req, res) => {
  const generate = !!req.body.generate;
  const typed = String(req.body.password || '').trim();
  if (!generate && typed.length < 8) {
    req.session.flash = { bad: true, html: 'That password is too short — use at least 8 characters.' };
    return res.redirect('/admin');
  }
  const pw = generate ? newPassword(10) : typed;
  const { rows } = await pool.query(
    `UPDATE users SET pass_hash=$1, must_change=$2 WHERE id=$3 AND role<>'owner' RETURNING username`,
    [bcrypt.hashSync(pw, 12), generate, req.params.id]);
  forgetSeat(req.params.id);
  req.session.flash = rows[0]
    ? { html: `Password for <b>${esc(rows[0].username)}</b> is now <code>${esc(pw)}</code>` +
        (generate ? ' — they will choose their own on first sign-in.' : ' — send it to them.') }
    : { bad: true, html: 'That reviewer no longer exists.' };
  res.redirect('/admin');
});

app.post('/admin/toggle/:id', requireLogin, requireOwner, async (req, res) => {
  await pool.query(`UPDATE users SET disabled = NOT disabled WHERE id=$1 AND role<>'owner'`, [req.params.id]);
  forgetSeat(req.params.id);
  res.redirect('/admin');
});

/* Removes a reviewer AND everything they wrote. Deliberately separate from
   Disable, which keeps their comments. Rows already copied to the Google Sheet
   stay there — this only clears our own database. */
app.post('/admin/delete/:id', requireLogin, requireOwner, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT username,(SELECT count(*)::int FROM comments c WHERE c.user_id=u.id) AS n
       FROM users u WHERE id=$1 AND role<>'owner'`, [req.params.id]);
  if (!rows[0]) { req.session.flash = { bad: true, html: 'That reviewer no longer exists.' }; return res.redirect('/admin'); }
  await pool.query(`DELETE FROM users WHERE id=$1 AND role<>'owner'`, [req.params.id]);
  forgetSeat(req.params.id);
  req.session.flash = { html: `Deleted <b>${esc(rows[0].username)}</b> and their ${rows[0].n} comment(s) from this app.` };
  res.redirect('/admin');
});

/* --------------------------------------------------------------------- api */
app.get('/api/me', requireLogin, (req, res) => {
  res.json({ ok: true, name: req.session.name, owner: req.session.role === 'owner' });
});

/* Owners see everything; reviewers see only their own rows. Enforced here,
   in the query — never in the browser. */
app.get('/api/comments', requireLogin, async (req, res) => {
  const owner = req.session.role === 'owner';
  const sql = `SELECT id,author,type,section,title,topic,body,shot_url,done,created_at,
                      (shot_data <> '') AS has_shot
               FROM comments ${owner ? '' : 'WHERE user_id=$1'} ORDER BY created_at`;
  const { rows } = await pool.query(sql, owner ? [] : [req.session.uid]);
  res.json({
    ok: true, owner,
    items: rows.map(r => ({
      id: r.id, name: r.author, type: r.type, section: r.section, title: r.title,
      topic: r.topic, text: r.body,
      shotUrl: r.shot_url || (r.has_shot ? '/api/shot/' + r.id : ''), done: r.done,
      ts: new Date(r.created_at).getTime()
    }))
  });
});

app.post('/api/comments', requireLogin, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [req.body];
  let saved = 0;
  for (const r of items) {
    if (!r || !r.id) continue;
    const shot = typeof r._shot === 'string' && r._shot.startsWith('data:') ? r._shot : '';
    const { rowCount } = await pool.query(
      `INSERT INTO comments (id,user_id,author,type,section,title,topic,body,shot_url,shot_data)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'',$9) ON CONFLICT (id) DO NOTHING`,
      [String(r.id), req.session.uid, req.session.name || '', r.type || 'Suggestion',
       r.section || '', r.title || '', r.topic || '', r.text || '', shot]);
    if (rowCount) { saved++; mirror(r, req.session); }
  }
  /* Only reports success once the rows are committed, so a reviewer is never
     told "sent" for something that is not stored. */
  res.json({ ok: true, saved });
});

app.post('/api/done/:id', requireLogin, async (req, res) => {
  const owner = req.session.role === 'owner';
  const { rowCount } = await pool.query(
    `UPDATE comments SET done=$1 WHERE id=$2 ${owner ? '' : 'AND user_id=$3'}`,
    owner ? [!!req.body.done, req.params.id] : [!!req.body.done, req.params.id, req.session.uid]);
  /* A reviewer asking about a comment that is not theirs gets the same answer
     as one asking about a comment that does not exist. */
  if (!rowCount) return res.status(404).json({ ok: false, error: 'not found' });
  res.json({ ok: true });
});

/* Keep the Google Sheet in step, so the triage workflow you already have
   carries on working. Failures here never block a reviewer. */
function mirror(rec, sess) {
  const url = process.env.SHEET_ENDPOINT;
  if (!url) return Promise.resolve(false);
  const payload = JSON.stringify({ key: sess.name || 'reviewer', items: [Object.assign({}, rec, { name: sess.name })] });
  return fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: payload })
    .then(r => r.text())
    .then(t => {
      const j = JSON.parse(t);
      if (!j.ok) throw new Error(j.error || 'sheet refused the row');
      const shotUrl = (j.shots && j.shots[rec.id]) || '';
      return pool.query('UPDATE comments SET mirrored=TRUE' + (shotUrl ? ', shot_url=$2' : '') + ' WHERE id=$1',
        shotUrl ? [rec.id, shotUrl] : [rec.id]).then(() => true);
    })
    .catch(err => { console.error('sheet mirror failed for ' + rec.id + ':', err.message); return false; });
}

/* Anything the Sheet did not accept is retried until it lands. The comment is
   already safe in our own database; this only keeps the Sheet complete. */
async function retryMirrors() {
  if (!process.env.SHEET_ENDPOINT) return;
  try {
    const { rows } = await pool.query(
      `SELECT id,author,type,section,title,topic,body,shot_data
         FROM comments WHERE mirrored=FALSE ORDER BY created_at LIMIT 25`);
    for (const r of rows) {
      await mirror({ id: r.id, type: r.type, section: r.section, title: r.title,
                     topic: r.topic, text: r.body, _shot: r.shot_data || undefined },
                   { name: r.author });
    }
    if (rows.length) console.log('retried ' + rows.length + ' unmirrored comment(s)');
  } catch (err) { console.error('mirror retry failed:', err.message); }
}
setInterval(retryMirrors, 5 * 60 * 1000).unref();

/* Screenshots are served from our own database, so they survive even if the
   Google copy is missing. */
app.get('/api/shot/:id', requireLogin, async (req, res) => {
  const owner = req.session.role === 'owner';
  const { rows } = await pool.query(
    `SELECT shot_data FROM comments WHERE id=$1 ${owner ? '' : 'AND user_id=$2'}`,
    owner ? [req.params.id] : [req.params.id, req.session.uid]);
  const d = rows[0] && rows[0].shot_data;
  if (!d) return res.status(404).send('no screenshot');
  const m = /^data:([^;]+);base64,(.*)$/.exec(d);
  if (!m) return res.status(404).send('no screenshot');
  /* No browser caching: on a shared computer the next person to sign in must
     not be served this image out of the cache instead of a fresh 404. */
  res.set('Content-Type', m[1])
     .set('Cache-Control', 'private, no-store, max-age=0')
     .set('Pragma', 'no-cache')
     .send(Buffer.from(m[2], 'base64'));
});

/* The page reports any send it could not complete. Reports are queued in the
   reviewer's browser and posted as soon as the connection is back, so a failure
   that happened offline still reaches you. */
app.post('/api/issue', requireLogin, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [req.body];
  for (const i of items.slice(0, 20)) {
    await pool.query(
      `INSERT INTO issues (user_id,username,kind,detail,comment_id) VALUES ($1,$2,$3,$4,$5)`,
      [req.session.uid, req.session.name || '', String(i.kind || 'send-failed').slice(0, 40),
       String(i.detail || '').slice(0, 500), String(i.commentId || '').slice(0, 60)]);
  }
  res.json({ ok: true });
});

app.post('/admin/issues/clear', requireLogin, requireOwner, async (req, res) => {
  await pool.query('UPDATE issues SET resolved=TRUE WHERE resolved=FALSE');
  req.session.flash = { html: 'Marked all reported problems as looked at.' };
  res.redirect('/admin');
});

/* Push any backlog to the Sheet immediately, rather than waiting for the timer. */
app.post('/admin/retry-mirror', requireLogin, requireOwner, async (req, res) => {
  await retryMirrors();
  const { rows } = await pool.query(
    `SELECT count(*) FILTER (WHERE NOT mirrored)::int AS pending FROM comments`);
  req.session.flash = rows[0].pending
    ? { bad: true, html: `${rows[0].pending} comment(s) still not in the Sheet — they are safe here and will keep retrying.` }
    : { html: 'Every comment is in the Google Sheet.' };
  res.redirect('/admin');
});

/* A one-click snapshot of everything, so you are never dependent on one system. */
app.get('/admin/export.json', requireLogin, requireOwner, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.id,c.author,c.type,c.section,c.title,c.topic,c.body,c.shot_url,
            (c.shot_data <> '') AS has_screenshot, c.done, c.mirrored, c.created_at,
            u.username
       FROM comments c JOIN users u ON u.id=c.user_id ORDER BY c.created_at`);
  res.set('Content-Disposition', 'attachment; filename="academy-comments-' +
    new Date().toISOString().slice(0, 10) + '.json"');
  res.json({ exported: new Date().toISOString(), count: rows.length, comments: rows });
});

/* Health check doubles as a delivery report. */
app.get('/api/status', requireLogin, requireOwner, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE mirrored)::int AS in_sheet,
            count(*) FILTER (WHERE NOT mirrored)::int AS pending,
            count(*) FILTER (WHERE shot_data <> '')::int AS with_screenshots
       FROM comments`);
  const iss = await pool.query(`SELECT count(*)::int AS open_issues FROM issues WHERE resolved=FALSE`);
  res.json({ ok: true, sheetConfigured: !!process.env.SHEET_ENDPOINT, ...rows[0], ...iss.rows[0] });
});

app.get('/healthz', (_req, res) => res.send('ok'));

initDb()
  .then(() => app.listen(PORT, () => console.log('Academy listening on ' + PORT)))
  .catch(err => { console.error('startup failed', err); process.exit(1); });
