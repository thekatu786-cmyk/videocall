const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');
const PORT = process.env.PORT || 3000;
const DB = path.join(__dirname, 'users.json');

let users = {};
try { users = JSON.parse(fs.readFileSync(DB)); } catch (e) {}
const save = () => fs.writeFileSync(DB, JSON.stringify(users));

const tokens = new Map(); // token -> username
const online = new Map(); // username -> ws
const busy = new Map();   // username -> other username (ringing or in call)
const fails = new Map();  // ip -> {n, t}

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const send = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
const body = req => new Promise(r => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); });
  req.on('end', () => { try { r(JSON.parse(d)); } catch (e) { r({}); } });
});

const server = http.createServer(async (req, res) => {
  const out = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };

  if (req.method === 'POST' && (req.url === '/api/register' || req.url === '/api/login')) {
    const ip = req.socket.remoteAddress;
    const f = fails.get(ip) || { n: 0, t: Date.now() };
    if (Date.now() - f.t > 600000) { f.n = 0; f.t = Date.now(); }
    if (f.n >= 10) return out(429, { error: 'Bahut try ho gaye, 10 min baad aao' });

    const b = await body(req);
    const u = String(b.username || '').toLowerCase().trim(), p = String(b.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return out(400, { error: 'Username 3-20 letters/numbers/_ ka ho' });
    if (p.length < 6) return out(400, { error: 'Password kam se kam 6 character ka ho' });

    if (req.url === '/api/register') {
      if (users[u]) return out(400, { error: 'Ye username pehle se hai' });
      const salt = crypto.randomBytes(16).toString('hex');
      users[u] = { salt, hash: hash(p, salt), display: u, avatar: '' };
      save();
    } else {
      const x = users[u];
      const ok = x && crypto.timingSafeEqual(Buffer.from(hash(p, x.salt), 'hex'), Buffer.from(x.hash, 'hex'));
      if (!ok) { f.n++; fails.set(ip, f); return out(401, { error: 'Username ya password galat hai' }); }
    }
    const t = crypto.randomBytes(24).toString('hex');
    tokens.set(t, u);
    return out(200, { token: t, username: u, display: users[u].display, avatar: users[u].avatar });
  }

  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    return fs.readFile(path.join(__dirname, 'public', 'index.html'), (e, d) => {
      if (e) { res.writeHead(500); return res.end('index.html nahi mila'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(d);
    });
  }
  res.writeHead(404); res.end('Not found');
});

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2e5 });

wss.on('connection', (ws, req) => {
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  const me = tokens.get(token);
  if (!me || !users[me]) { ws.close(4001); return; }

  const old = online.get(me);
  if (old && old !== ws) old.close(4002);
  online.set(me, ws);

  const info = u => ({ username: u, display: users[u].display, avatar: users[u].avatar, online: online.has(u) });
  const partnerOf = () => busy.get(me);
  const clear = () => { const o = busy.get(me); busy.delete(me); if (o) busy.delete(o); return o; };

  ws.on('message', m => {
    let d; try { d = JSON.parse(m); } catch (e) { return; }

    if (d.t === 'search') {
      const q = String(d.q || '').toLowerCase().trim();
      const list = Object.keys(users)
        .filter(u => u !== me && (u.includes(q) || users[u].display.toLowerCase().includes(q)))
        .slice(0, 20).map(info);
      send(ws, { t: 'results', list });

    } else if (d.t === 'profile') {
      users[me].display = String(d.display || me).slice(0, 30);
      if (typeof d.avatar === 'string' && d.avatar.length < 60000) users[me].avatar = d.avatar;
      save();

    } else if (d.t === 'call') {
      const to = String(d.to);
      if (!users[to] || to === me) return;
      if (!online.has(to)) return send(ws, { t: 'unavailable', why: 'offline' });
      if (busy.has(to) || busy.has(me)) return send(ws, { t: 'unavailable', why: 'busy' });
      busy.set(me, to); busy.set(to, me);
      send(online.get(to), { t: 'incoming', from: info(me) });

    } else if (d.t === 'accept') {
      send(online.get(partnerOf()), { t: 'accepted' });

    } else if (d.t === 'reject') {
      const o = clear(); send(online.get(o), { t: 'rejected' });

    } else if (d.t === 'end') {
      const o = clear(); send(online.get(o), { t: 'ended' });

    } else if (d.t === 'signal') {
      send(online.get(partnerOf()), { t: 'signal', data: d.data });
    }
  });

  ws.on('close', () => {
    if (online.get(me) === ws) {
      const o = clear(); send(online.get(o), { t: 'ended' });
      online.delete(me);
    }
  });
});

server.listen(PORT, () => console.log('Server chal raha hai: http://localhost:' + PORT));
