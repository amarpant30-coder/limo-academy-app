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
      done       BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS comments_user_idx ON comments(user_id);
  `);

  /* Owner account. If ADMIN_PASS is set it is applied on every boot, so the
     owner can always recover access by changing that variable in Railway.
     Remove ADMIN_PASS once you are in and the password is managed in-app. */
  const user = (process.env.ADMIN_USER || 'amar').toLowerCase().trim();
  const envPass = process.env.ADMIN_PASS;
  const { rows } = await pool.query(`SELECT count(*)::int AS n FROM users WHERE role='owner'`);

  if (rows[0].n === 0) {
    const pass = envPass || crypto.randomBytes(6).toString('base64url');
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
function requireLogin(req, res, next) {
  if (!req.session.uid) {
    return req.path.startsWith('/api/')
      ? res.status(401).json({ ok: false, error: 'not signed in' })
      : res.redirect('/login');
  }
  next();
}
function requireOwner(req, res, next) {
  if (req.session.role !== 'owner') return res.status(403).send('Not allowed');
  next();
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
a{color:#e8532b}
code{background:#f3f4f7;padding:2px 6px;border-radius:5px;font-size:.88rem}
</style></head><body>${body}</body></html>`;
}

app.get('/login', (req, res) => {
  if (req.session.uid) return res.redirect('/');
  const bad = req.query.e ? '<div class="err">That username or password was not right.</div>' : '';
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
  const msg = req.query.new
    ? `<div class="ok">Created <b>${esc(req.query.new)}</b> with starting password <code>${esc(req.query.pw)}</code> — send it to them; they will set their own on first sign-in.</div>`
    : (req.query.reset
      ? `<div class="ok">New starting password for <b>${esc(req.query.reset)}</b>: <code>${esc(req.query.pw)}</code></div>` : '');
  const list = rows.map(u => `<tr>
      <td><b>${esc(u.username)}</b>${u.role==='owner'?' · owner':''}${u.disabled?' · disabled':''}</td>
      <td>${esc(u.name)}</td>
      <td>${u.comments}</td>
      <td>${u.must_change ? 'not signed in yet' : 'active'}</td>
      <td>${u.role==='owner' ? '' : `
        <form method="post" action="/admin/reset/${u.id}" style="display:inline"><button class="mini">Reset password</button></form>
        <form method="post" action="/admin/toggle/${u.id}" style="display:inline"><button class="mini">${u.disabled?'Enable':'Disable'}</button></form>`}</td>
    </tr>`).join('');
  res.send(shell('Reviewers — Reservations Academy', `<div class="card wide">
    <h1>Reviewers</h1>
    <p class="sub">Add a reviewer, hand them the username and starting password, and they set their own on first sign-in.
      <a href="/">Open the module</a> · <a href="/logout">Sign out</a></p>
    ${msg}
    <form method="post" action="/admin/create" class="row">
      <div><label for="nu">Username</label><input id="nu" name="username" placeholder="priya" required autocapitalize="none"></div>
      <div><label for="nn">Full name</label><input id="nn" name="name" placeholder="Priya Nair"></div>
      <button type="submit">Add reviewer</button>
    </form>
    <table><thead><tr><th>Username</th><th>Name</th><th>Comments</th><th>Status</th><th></th></tr></thead>
    <tbody>${list}</tbody></table>
  </div>`));
});

app.post('/admin/create', requireLogin, requireOwner, async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 40);
  if (!username) return res.redirect('/admin');
  const pw = crypto.randomBytes(5).toString('base64url');
  try {
    await pool.query(
      `INSERT INTO users (username,name,pass_hash,role,must_change) VALUES ($1,$2,$3,'reviewer',TRUE)`,
      [username, String(req.body.name || '').slice(0, 80), bcrypt.hashSync(pw, 12)]);
    res.redirect('/admin?new=' + encodeURIComponent(username) + '&pw=' + encodeURIComponent(pw));
  } catch (err) {
    res.redirect('/admin');
  }
});

app.post('/admin/reset/:id', requireLogin, requireOwner, async (req, res) => {
  const pw = crypto.randomBytes(5).toString('base64url');
  const { rows } = await pool.query(
    `UPDATE users SET pass_hash=$1, must_change=TRUE WHERE id=$2 AND role<>'owner' RETURNING username`,
    [bcrypt.hashSync(pw, 12), req.params.id]);
  if (!rows[0]) return res.redirect('/admin');
  res.redirect('/admin?reset=' + encodeURIComponent(rows[0].username) + '&pw=' + encodeURIComponent(pw));
});

app.post('/admin/toggle/:id', requireLogin, requireOwner, async (req, res) => {
  await pool.query(`UPDATE users SET disabled = NOT disabled WHERE id=$1 AND role<>'owner'`, [req.params.id]);
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
  const sql = `SELECT id,author,type,section,title,topic,body,shot_url,done,created_at
               FROM comments ${owner ? '' : 'WHERE user_id=$1'} ORDER BY created_at`;
  const { rows } = await pool.query(sql, owner ? [] : [req.session.uid]);
  res.json({
    ok: true, owner,
    items: rows.map(r => ({
      id: r.id, name: r.author, type: r.type, section: r.section, title: r.title,
      topic: r.topic, text: r.body, shotUrl: r.shot_url, done: r.done,
      ts: new Date(r.created_at).getTime()
    }))
  });
});

app.post('/api/comments', requireLogin, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [req.body];
  let saved = 0;
  for (const r of items) {
    if (!r || !r.id) continue;
    const { rowCount } = await pool.query(
      `INSERT INTO comments (id,user_id,author,type,section,title,topic,body,shot_url)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
      [String(r.id), req.session.uid, req.session.name || '', r.type || 'Suggestion',
       r.section || '', r.title || '', r.topic || '', r.text || '', '']);
    if (rowCount) { saved++; mirror(r, req.session); }
  }
  res.json({ ok: true, saved });
});

app.post('/api/done/:id', requireLogin, async (req, res) => {
  const owner = req.session.role === 'owner';
  await pool.query(
    `UPDATE comments SET done=$1 WHERE id=$2 ${owner ? '' : 'AND user_id=$3'}`,
    owner ? [!!req.body.done, req.params.id] : [!!req.body.done, req.params.id, req.session.uid]);
  res.json({ ok: true });
});

/* Keep the Google Sheet in step, so the triage workflow you already have
   carries on working. Failures here never block a reviewer. */
function mirror(rec, sess) {
  const url = process.env.SHEET_ENDPOINT;
  if (!url) return;
  const payload = JSON.stringify({ key: sess.name || 'reviewer', items: [Object.assign({}, rec, { name: sess.name })] });
  fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: payload })
    .then(r => r.text())
    .then(t => { try { const j = JSON.parse(t); if (j.shots && j.shots[rec.id])
      pool.query('UPDATE comments SET shot_url=$1 WHERE id=$2', [j.shots[rec.id], rec.id]).catch(()=>{});
    } catch (e) {} })
    .catch(err => console.error('sheet mirror failed:', err.message));
}

app.get('/healthz', (_req, res) => res.send('ok'));

initDb()
  .then(() => app.listen(PORT, () => console.log('Academy listening on ' + PORT)))
  .catch(err => { console.error('startup failed', err); process.exit(1); });
