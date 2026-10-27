const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3001);
const ROOT = __dirname;
const DB_DIR = path.join(ROOT, 'data');
const DB_PATH = path.join(DB_DIR, 'barbearia.db');
const SESSION_TTL = 30 * 60 * 1000;
const SESSION_COOKIE = 'gb_session';
const defaultEncryptionKey = crypto.createHash('sha256').update('saep-local-development-key-change-before-deploy').digest();
const encryptionSecret = process.env.DATA_ENCRYPTION_KEY || 'saep-local-development-key-change-before-deploy';
const encryptionKey = crypto.createHash('sha256').update(encryptionSecret).digest();
const lookupKey = crypto.createHmac('sha256', encryptionKey).update('cpf-lookup').digest();
const sessions = new Map();

fs.mkdirSync(DB_DIR, { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON');
db.exec(fs.readFileSync(path.join(ROOT, 'saep_db.sql'), 'utf8'));

function seal(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return {
    cpf_iv: iv.toString('hex'),
    cpf_tag: cipher.getAuthTag().toString('hex'),
    cpf_encrypted: encrypted.toString('hex'),
    cpf_hash: crypto.createHmac('sha256', lookupKey).update(value).digest('hex')
  };
}

function unsealWithKey(record, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.cpf_iv, 'hex'));
  decipher.setAuthTag(Buffer.from(record.cpf_tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(record.cpf_encrypted, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

function unseal(record) {
  return unsealWithKey(record, encryptionKey);
}

function initializeEncryptionKey() {
  const fingerprintPath = path.join(DB_DIR, 'cpf-key-id');
  const fingerprint = crypto.createHash('sha256').update(encryptionKey).digest('hex');
  if (fs.existsSync(fingerprintPath)) {
    if (fs.readFileSync(fingerprintPath, 'utf8').trim() !== fingerprint) {
      throw new Error('A chave DATA_ENCRYPTION_KEY nao corresponde aos dados existentes. Restaure a chave original ou migre os CPFs antes de iniciar.');
    }
    return;
  }

  for (const table of ['clientes', 'barbeiros']) {
    const records = db.prepare(`SELECT id, cpf_iv, cpf_tag, cpf_encrypted FROM ${table}`).all();
    const update = db.prepare(`UPDATE ${table} SET cpf_iv = ?, cpf_tag = ?, cpf_encrypted = ? WHERE id = ?`);
    for (const record of records) {
      const plaintext = unsealWithKey(record, defaultEncryptionKey);
      const encrypted = seal(plaintext);
      update.run(encrypted.cpf_iv, encrypted.cpf_tag, encrypted.cpf_encrypted, record.id);
    }
  }
  fs.writeFileSync(fingerprintPath, fingerprint, { mode: 0o600 });
}

initializeEncryptionKey();

function maskCpf(value) {
  return `***.***.***-${value.slice(-2)}`;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, stored) {
  const [scheme, salt, expectedHex] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !expectedHex) return false;
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function json(response, status, value, headers = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  response.end(JSON.stringify(value));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let raw = '';
    request.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1024 * 1024) reject(new Error('Requisicao muito grande.'));
    });
    request.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Corpo JSON invalido.'));
      }
    });
    request.on('error', reject);
  });
}

function getSession(request) {
  const cookie = request.headers.cookie || '';
  const token = cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  const session = token && sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function requireSession(request, response) {
  const session = getSession(request);
  if (!session) {
    json(response, 401, { error: 'Sua sessao expirou. Entre novamente.' });
    return null;
  }
  return session;
}

function parseId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function validateCpf(value) {
  const digits = String(value || '').replace(/\D/g, '');
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return null;
  for (let index = 9; index < 11; index += 1) {
    let sum = 0;
    for (let digit = 0; digit < index; digit += 1) sum += Number(digits[digit]) * (index + 1 - digit);
    const check = (sum * 10) % 11 % 10;
    if (check !== Number(digits[index])) return null;
  }
  return digits;
}

function requireText(value, label, max = 120) {
  const text = String(value || '').trim();
  if (!text || text.length > max) throw new Error(`${label} e obrigatorio (ate ${max} caracteres).`);
  return text;
}

function getClientPayload(row) {
  const cpf = unseal(row);
  return { id: row.id, name: row.name, phone: row.phone, email: row.email, cpf: maskCpf(cpf) };
}

function getBarberPayload(row) {
  const cpf = unseal(row);
  return { id: row.id, name: row.name, phone: row.phone, specialty: row.specialty, cpf: maskCpf(cpf) };
}

function handleApi(request, response, url) {
  const method = request.method;
  const pathname = url.pathname;

  if (method === 'POST' && pathname === '/api/login') {
    return readBody(request).then(body => {
      const username = String(body.username || '').trim().toLowerCase();
      const user = db.prepare('SELECT id, name, username, password_hash FROM usuarios WHERE username = ? COLLATE NOCASE').get(username);
      if (!user || !verifyPassword(String(body.password || ''), user.password_hash)) {
        return json(response, 401, { error: 'Usuario ou senha invalidos.' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { userId: user.id, name: user.name, expiresAt: Date.now() + SESSION_TTL });
      const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
      return json(response, 200, { name: user.name }, {
        'Set-Cookie': `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800${secure}`
      });
    });
  }

  if (method === 'POST' && pathname === '/api/logout') {
    const session = getSession(request);
    if (session) sessions.delete(session.token);
    return json(response, 200, { ok: true }, {
      'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
    });
  }

  const session = requireSession(request, response);
  if (!session) return Promise.resolve();

  if (method === 'GET' && pathname === '/api/me') return json(response, 200, { name: session.name });

  if (method === 'GET' && pathname === '/api/dashboard') {
    const counts = {
      clients: db.prepare('SELECT COUNT(*) AS count FROM clientes').get().count,
      barbers: db.prepare('SELECT COUNT(*) AS count FROM barbeiros').get().count,
      services: db.prepare('SELECT COUNT(*) AS count FROM servicos').get().count,
      appointments: db.prepare("SELECT COUNT(*) AS count FROM agendamentos WHERE status = 'Agendado'").get().count
    };
    const upcoming = db.prepare(`
      SELECT a.id, a.starts_at, a.status, c.name AS client_name, b.name AS barber_name, s.name AS service_name
      FROM agendamentos a
      JOIN clientes c ON c.id = a.client_id
      JOIN barbeiros b ON b.id = a.barber_id
      JOIN servicos s ON s.id = a.service_id
      WHERE a.starts_at >= strftime('%Y-%m-%dT%H:%M:%S', 'now', 'localtime') AND a.status = 'Agendado'
      ORDER BY a.starts_at LIMIT 5
    `).all();
    return json(response, 200, { counts, upcoming });
  }

  if (method === 'GET' && pathname === '/api/clients') {
    const term = `%${String(url.searchParams.get('q') || '').trim()}%`;
    const rows = db.prepare(`SELECT * FROM clientes WHERE name LIKE ? OR phone LIKE ? OR email LIKE ? ORDER BY name`).all(term, term, term);
    return json(response, 200, rows.map(getClientPayload));
  }

  if (method === 'POST' && pathname === '/api/clients') {
    return readBody(request).then(body => {
      const name = requireText(body.name, 'Nome');
      const cpf = validateCpf(body.cpf);
      if (!cpf) throw new Error('Informe um CPF valido.');
      const phone = requireText(body.phone, 'Telefone', 24);
      const email = requireText(body.email, 'E-mail', 160);
      const encrypted = seal(cpf);
      const result = db.prepare(`INSERT INTO clientes(name, phone, email, cpf_iv, cpf_tag, cpf_encrypted, cpf_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(name, phone, email, encrypted.cpf_iv, encrypted.cpf_tag, encrypted.cpf_encrypted, encrypted.cpf_hash);
      return json(response, 201, { id: Number(result.lastInsertRowid) });
    });
  }

  const clientMatch = pathname.match(/^\/api\/clients\/(\d+)$/);
  if (clientMatch && method === 'PUT') {
    return readBody(request).then(body => {
      const id = parseId(clientMatch[1]);
      const current = db.prepare('SELECT * FROM clientes WHERE id = ?').get(id);
      if (!current) return json(response, 404, { error: 'Cliente nao encontrado.' });
      const cpf = body.cpf ? validateCpf(body.cpf) : unseal(current);
      if (!cpf) throw new Error('Informe um CPF valido.');
      const encrypted = body.cpf ? seal(cpf) : current;
      db.prepare(`UPDATE clientes SET name = ?, phone = ?, email = ?, cpf_iv = ?, cpf_tag = ?, cpf_encrypted = ?, cpf_hash = ? WHERE id = ?`)
        .run(requireText(body.name, 'Nome'), requireText(body.phone, 'Telefone', 24), requireText(body.email, 'E-mail', 160), encrypted.cpf_iv, encrypted.cpf_tag, encrypted.cpf_encrypted, encrypted.cpf_hash, id);
      return json(response, 200, { ok: true });
    });
  }
  if (clientMatch && method === 'DELETE') return deleteRecord(response, 'clientes', clientMatch[1]);

  if (method === 'GET' && pathname === '/api/barbers') {
    return json(response, 200, db.prepare('SELECT * FROM barbeiros ORDER BY name').all().map(getBarberPayload));
  }
  if (method === 'POST' && pathname === '/api/barbers') {
    return readBody(request).then(body => {
      const cpf = validateCpf(body.cpf);
      if (!cpf) throw new Error('Informe um CPF valido.');
      const encrypted = seal(cpf);
      const result = db.prepare(`INSERT INTO barbeiros(name, phone, specialty, cpf_iv, cpf_tag, cpf_encrypted, cpf_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(requireText(body.name, 'Nome'), requireText(body.phone, 'Telefone', 24), requireText(body.specialty, 'Especialidade'), encrypted.cpf_iv, encrypted.cpf_tag, encrypted.cpf_encrypted, encrypted.cpf_hash);
      return json(response, 201, { id: Number(result.lastInsertRowid) });
    });
  }
  const barberMatch = pathname.match(/^\/api\/barbers\/(\d+)$/);
  if (barberMatch && method === 'PUT') {
    return readBody(request).then(body => {
      const id = parseId(barberMatch[1]);
      const current = db.prepare('SELECT * FROM barbeiros WHERE id = ?').get(id);
      if (!current) return json(response, 404, { error: 'Barbeiro nao encontrado.' });
      const cpf = body.cpf ? validateCpf(body.cpf) : unseal(current);
      if (!cpf) throw new Error('Informe um CPF valido.');
      const encrypted = body.cpf ? seal(cpf) : current;
      db.prepare(`UPDATE barbeiros SET name = ?, phone = ?, specialty = ?, cpf_iv = ?, cpf_tag = ?, cpf_encrypted = ?, cpf_hash = ? WHERE id = ?`)
        .run(requireText(body.name, 'Nome'), requireText(body.phone, 'Telefone', 24), requireText(body.specialty, 'Especialidade'), encrypted.cpf_iv, encrypted.cpf_tag, encrypted.cpf_encrypted, encrypted.cpf_hash, id);
      return json(response, 200, { ok: true });
    });
  }
  if (barberMatch && method === 'DELETE') return deleteRecord(response, 'barbeiros', barberMatch[1]);

  if (method === 'GET' && pathname === '/api/services') return json(response, 200, db.prepare('SELECT * FROM servicos ORDER BY name').all());
  if (method === 'POST' && pathname === '/api/services') {
    return readBody(request).then(body => {
      const duration = Number(body.duration);
      const price = Number(body.price);
      if (!Number.isInteger(duration) || duration < 10 || duration > 480) throw new Error('Duracao invalida (10 a 480 minutos).');
      if (!Number.isFinite(price) || price < 0) throw new Error('Informe um preco valido.');
      const result = db.prepare('INSERT INTO servicos(name, duration, price) VALUES (?, ?, ?)')
        .run(requireText(body.name, 'Nome do servico'), duration, price);
      return json(response, 201, { id: Number(result.lastInsertRowid) });
    });
  }
  const serviceMatch = pathname.match(/^\/api\/services\/(\d+)$/);
  if (serviceMatch && method === 'PUT') {
    return readBody(request).then(body => {
      const duration = Number(body.duration);
      const price = Number(body.price);
      if (!Number.isInteger(duration) || duration < 10 || duration > 480) throw new Error('Duracao invalida (10 a 480 minutos).');
      if (!Number.isFinite(price) || price < 0) throw new Error('Informe um preco valido.');
      const result = db.prepare('UPDATE servicos SET name = ?, duration = ?, price = ? WHERE id = ?')
        .run(requireText(body.name, 'Nome do servico'), duration, price, parseId(serviceMatch[1]));
      if (!result.changes) return json(response, 404, { error: 'Servico nao encontrado.' });
      return json(response, 200, { ok: true });
    });
  }
  if (serviceMatch && method === 'DELETE') return deleteRecord(response, 'servicos', serviceMatch[1]);

  if (method === 'GET' && pathname === '/api/appointments') {
    const rows = db.prepare(`SELECT a.id, a.starts_at, a.status, a.notes, a.client_id, a.barber_id, a.service_id,
      c.name AS client_name, c.phone AS client_phone, c.email AS client_email,
      b.name AS barber_name, b.phone AS barber_phone, b.specialty AS barber_specialty,
      s.name AS service_name, s.duration AS service_duration, s.price AS service_price
      FROM agendamentos a JOIN clientes c ON c.id = a.client_id
      JOIN barbeiros b ON b.id = a.barber_id JOIN servicos s ON s.id = a.service_id
      ORDER BY a.starts_at, a.id`).all();
    return json(response, 200, rows);
  }
  if (method === 'POST' && pathname === '/api/appointments') {
    return readBody(request).then(body => {
      const clientId = parseId(body.client_id);
      const barberId = parseId(body.barber_id);
      const serviceId = parseId(body.service_id);
      const start = new Date(body.starts_at);
      if (!clientId || !barberId || !serviceId) throw new Error('Cliente, barbeiro e servico sao obrigatorios.');
      if (Number.isNaN(start.getTime())) throw new Error('Data e horario invalidos.');
      const service = db.prepare('SELECT duration FROM servicos WHERE id = ?').get(serviceId);
      if (!service || !db.prepare('SELECT id FROM clientes WHERE id = ?').get(clientId) || !db.prepare('SELECT id FROM barbeiros WHERE id = ?').get(barberId)) {
        throw new Error('Selecione cliente, barbeiro e servico cadastrados.');
      }
      const startTime = start.getTime();
      const endTime = startTime + service.duration * 60000;
      const existing = db.prepare(`SELECT a.starts_at, s.duration FROM agendamentos a JOIN servicos s ON s.id = a.service_id
        WHERE a.barber_id = ? AND a.status = 'Agendado'`).all(barberId);
      const conflict = existing.some(item => {
        const existingStart = new Date(item.starts_at).getTime();
        return startTime < existingStart + item.duration * 60000 && endTime > existingStart;
      });
      if (conflict) throw new Error('Este barbeiro ja possui atendimento nesse horario.');
      const startsAt = `${body.starts_at}:00`;
      const result = db.prepare(`INSERT INTO agendamentos(client_id, barber_id, service_id, starts_at, status, notes)
        VALUES (?, ?, ?, ?, 'Agendado', ?)`).run(clientId, barberId, serviceId, startsAt, String(body.notes || '').trim().slice(0, 300));
      return json(response, 201, { id: Number(result.lastInsertRowid) });
    });
  }
  const appointmentMatch = pathname.match(/^\/api\/appointments\/(\d+)$/);
  if (appointmentMatch && method === 'PATCH') {
    return readBody(request).then(body => {
      const status = ['Agendado', 'Concluido', 'Cancelado'].includes(body.status) ? body.status : null;
      if (!status) throw new Error('Status invalido.');
      const result = db.prepare('UPDATE agendamentos SET status = ? WHERE id = ?').run(status, parseId(appointmentMatch[1]));
      if (!result.changes) return json(response, 404, { error: 'Agendamento nao encontrado.' });
      return json(response, 200, { ok: true });
    });
  }
  if (appointmentMatch && method === 'DELETE') return deleteRecord(response, 'agendamentos', appointmentMatch[1]);

  return json(response, 404, { error: 'Rota nao encontrada.' });
}

function deleteRecord(response, table, rawId) {
  const id = parseId(rawId);
  if (!id) return json(response, 400, { error: 'Identificador invalido.' });
  const result = db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
  if (!result.changes) return json(response, 404, { error: 'Registro nao encontrado.' });
  return json(response, 200, { ok: true });
}

const mimeTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (url.pathname.startsWith('/api/')) {
    Promise.resolve().then(() => handleApi(request, response, url)).catch(error => {
      if (error.errcode === 2067 || error.errcode === 1555) return json(response, 409, { error: 'Ja existe um registro com esse CPF ou nome.' });
      if (error.errcode === 787 || error.errcode === 1811) return json(response, 409, { error: 'Nao e possivel excluir: ha registros vinculados.' });
      return json(response, 400, { error: error.message || 'Nao foi possivel concluir a operacao.' });
    });
    return;
  }
  const requested = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const file = path.resolve(ROOT, 'public', `.${requested}`);
  if (!file.startsWith(path.resolve(ROOT, 'public') + path.sep)) return json(response, 403, { error: 'Acesso negado.' });
  fs.readFile(file, (error, content) => {
    if (error) return json(response, 404, { error: 'Arquivo nao encontrado.' });
    response.writeHead(200, { 'Content-Type': mimeTypes[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
    response.end(content);
  });
});

server.listen(PORT, () => console.log(`Sistema Barbearia disponivel em http://localhost:${PORT}`));
process.on('SIGINT', () => { db.close(); server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { db.close(); server.close(() => process.exit(0)); });