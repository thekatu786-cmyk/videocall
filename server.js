
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DB = path.join(__dirname, 'users.json');
const HTML = path.join(__dirname, 'public', 'index.html');

let users = {};

try {
  users = JSON.parse(fs.readFileSync(DB, 'utf8'));
} catch {
  users = {};
}

function save() {
  fs.writeFileSync(DB, JSON.stringify(users, null, 2));
}

const tokens = new Map();
const online = new Map();
const busy = new Map();
const fails = new Map();

const hash = (password, salt) =>
  crypto.scryptSync(password, salt, 64).toString('hex');

const send = (ws, data) => {
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
};

function getBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';

    req.on('data', chunk => {
      data += chunk;
      if (data.length > 100000) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve({});
      }
    });

    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const out = (code, data) => {
    if (res.headersSent) return;
    res.writeHead(code, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify(data));
  };

  const url = new URL(req.url, 'http://localhost');
  const route = url.pathname;

  // Health check
  if (req.method === 'GET' && route === '/health') {
    return out(200, { status: 'ok', service: 'HEGUYS' });
  }

  // Homepage
  if (req.method === 'GET' &&
      (route === '/' || route === '/index.html')) {

    if (!fs.existsSync(HTML)) {
      res.writeHead(500, {
        'Content-Type': 'text/plain; charset=utf-8'
      });
      return res.end(
        'index.html nahi mila. File ko public/index.html mein rakho.'
      );
    }

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    });

    return fs.createReadStream(HTML).pipe(res);
  }

  // Register / Login
  if (req.method === 'POST' &&
      (route === '/api/register' || route === '/api/login')) {

    const ip = req.socket.remoteAddress || 'unknown';
    const f = fails.get(ip) || { n: 0, t: Date.now() };

    if (Date.now() - f.t > 600000) {
      f.n = 0;
      f.t = Date.now();
    }

    if (f.n >= 10) {
      return out(429, {
        error: 'Bahut try ho gaye. 10 minute baad try karo.'
      });
    }

    let b;

    try {
      b = await getBody(req);
    } catch {
      return out(413, { error: 'Request bahut badi hai' });
    }

    const u = String(b.username || '').toLowerCase().trim();
    const p = String(b.password || '');

    if (!/^[a-z0-9_]{3,20}$/.test(u)) {
      return out(400, {
        error: 'Username 3-20 letters/numbers/_ ka hona chahiye'
      });
    }

    if (p.length < 6 || p.length > 200) {
      return out(400, {
        error: 'Password 6-200 characters ka hona chahiye'
      });
    }

    if (route === '/api/register') {
      if (users[u]) {
        return out(400, { error: 'Ye username pehle se hai' });
      }

      const salt = crypto.randomBytes(16).toString('hex');

      users[u] = {
        salt,
        hash: hash(p, salt),
        display: u,
        avatar: ''
      };

      try {
        save();
      } catch {
        delete users[u];
        return out(500, { error: 'Account save nahi ho paya' });
      }

    } else {
      const user = users[u];

      let valid = false;

      if (user && user.salt && user.hash) {
        const calculated = Buffer.from(hash(p, user.salt), 'hex');
        const stored = Buffer.from(user.hash, 'hex');

        valid =
          calculated.length === stored.length &&
          crypto.timingSafeEqual(calculated, stored);
      }

      if (!valid) {
        f.n++;
        fails.set(ip, f);

        return out(401, {
          error: 'Username ya password galat hai'
        });
      }

      fails.delete(ip);
    }

    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, u);

    return out(200, {
      token,
      username: u,
      display: users[u].display,
      avatar: users[u].avatar
    });
  }

  res.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Not found');
});

// WebSocket
const wss = new WebSocketServer({
  server,
  path: '/ws',
  maxPayload: 200000
});

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  const me = tokens.get(token);

  if (!me || !users[me]) {
    ws.close(4001);
    return;
  }

  const old = online.get(me);

  if (old && old !== ws) {
    old.close(4002);
  }

  online.set(me, ws);

  const info = username => {
    const u = users[username];
    if (!u) return null;

    return {
      username,
      display: u.display,
      avatar: u.avatar,
      online: online.has(username)
    };
  };

  const clear = () => {
    const other = busy.get(me);
    busy.delete(me);

    if (other && busy.get(other) === me) {
      busy.delete(other);
    }

    return other;
  };

  ws.on('message', message => {
    let d;

    try {
      d = JSON.parse(message.toString());
    } catch {
      return;
    }

    if (d.t === 'search') {
      const q = String(d.q || '').toLowerCase().trim();

      const list = Object.keys(users)
        .filter(u =>
          u !== me &&
          (u.includes(q) ||
          String(users[u].display).toLowerCase().includes(q))
        )
        .slice(0, 20)
        .map(info);

      send(ws, { t: 'results', list });
    }

    else if (d.t === 'profile') {
      users[me].display =
        String(d.display || me).trim().slice(0, 30) || me;

      if (
        typeof d.avatar === 'string' &&
        d.avatar.length < 60000 &&
        (d.avatar === '' || d.avatar.startsWith('data:image/'))
      ) {
        users[me].avatar = d.avatar;
      }

      try {
        save();
        send(ws, { t: 'profile_saved' });
      } catch {
        send(ws, { t: 'error', message: 'Profile save nahi hua' });
      }
    }

    else if (d.t === 'call') {
      const to = String(d.to || '');

      if (!users[to] || to === me) return;

      if (!online.has(to)) {
        return send(ws, {
          t: 'unavailable',
          why: 'offline'
        });
      }

      if (busy.has(to) || busy.has(me)) {
        return send(ws, {
          t: 'unavailable',
          why: 'busy'
        });
      }

      busy.set(me, to);
      busy.set(to, me);

      send(online.get(to), {
        t: 'incoming',
        from: info(me)
      });
    }

    else if (d.t === 'accept') {
      const other = busy.get(me);
      if (other) send(online.get(other), { t: 'accepted' });
    }

    else if (d.t === 'reject') {
      const other = clear();
      if (other) send(online.get(other), { t: 'rejected' });
    }

    else if (d.t === 'end') {
      const other = clear();
      if (other) send(online.get(other), { t: 'ended' });
    }

    else if (d.t === 'signal') {
      const other = busy.get(me);

      if (other && d.data) {
        send(online.get(other), {
          t: 'signal',
          data: d.data
        });
      }
    }
  });

  ws.on('close', () => {
    if (online.get(me) === ws) {
      const other = clear();

      if (other) {
        send(online.get(other), { t: 'ended' });
      }

      online.delete(me);
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('HEGUYS Server running on port ' + PORT);
  console.log('HTML file:', HTML);
  console.log('HTML exists:', fs.existsSync(HTML));
});
