PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clientes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  cpf_iv TEXT NOT NULL,
  cpf_tag TEXT NOT NULL,
  cpf_encrypted TEXT NOT NULL,
  cpf_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS barbeiros (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  specialty TEXT NOT NULL,
  cpf_iv TEXT NOT NULL,
  cpf_tag TEXT NOT NULL,
  cpf_encrypted TEXT NOT NULL,
  cpf_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS servicos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  duration INTEGER NOT NULL CHECK(duration BETWEEN 10 AND 480),
  price REAL NOT NULL CHECK(price >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agendamentos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  barber_id INTEGER NOT NULL,
  service_id INTEGER NOT NULL,
  starts_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Agendado' CHECK(status IN ('Agendado', 'Concluido', 'Cancelado')),
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(client_id) REFERENCES clientes(id) ON DELETE RESTRICT,
  FOREIGN KEY(barber_id) REFERENCES barbeiros(id) ON DELETE RESTRICT,
  FOREIGN KEY(service_id) REFERENCES servicos(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_agendamentos_data ON agendamentos(starts_at, status);
CREATE INDEX IF NOT EXISTS idx_agendamentos_barbeiro ON agendamentos(barber_id, starts_at);

INSERT OR IGNORE INTO usuarios(id, name, username, password_hash) VALUES
  (1, 'Administrador', 'admin', 'scrypt$admin-seed-salt$e80e8813c18977784683cba8188b89eeeb16af7c51f921891fc7319c082bbe0c2e3afc699e28b678b27fc043ea3d8de903c804d2caeab095d77dbc84ab1e1e38'),
  (2, 'Marina Costa', 'marina', 'scrypt$marina-seed-salt$d609df3d538441bc5a5df89841e789adfc14a9f7645e28bcf03769150e3f56b46b9ae5045cb4f5e5beeb68e671b9c6d285d45500f169f4c0c436e3d1093eb8ae'),
  (3, 'Rafael Lima', 'rafael', 'scrypt$rafael-seed-salt$35ab42e2ea683c2a08a6eb5413b7cdfdbc3729a89425397d5ec292fee8369db5562c103f6f580fee30575a9e8971e4afe4a47e9099ea389481f04aadc01a48c7');

INSERT OR IGNORE INTO clientes(id, name, phone, email, cpf_iv, cpf_tag, cpf_encrypted, cpf_hash) VALUES
  (1, 'Lucas Almeida', '(11) 99911-1111', 'lucas@email.com', 'a58013bf11651a94b93d98f1', 'c4da9450e3729ab280169c98b53415a2', '36f8a8f40874c6156ea910', 'fcf3c14b35e59a33c64b805fd9b1588ca04360937a23ce776f2e8d397398b96d'),
  (2, 'Pedro Santos', '(11) 98822-2222', 'pedro@email.com', '94bc6b2b8b28fe85f455d0bb', 'c6a617b24ad2f39ba8f49e2c5340e108', 'b743483eeba7401773e71d', 'ff957449e88841cacce35600abba7cdc74b77dd6c4d27fc8e3ac19b3789e7e66'),
  (3, 'Caio Oliveira', '(11) 97733-3333', 'caio@email.com', 'f7c9c4f18e4db21beb8c54f8', '73488e5617df3e9ce3e51ab46af13cfb', '3926efaecb441fe76c80bd', 'c873f526d889786d003a6cefefdf4227df6c1d0d6d5ad5e2fa5a2b84314142fb');

INSERT OR IGNORE INTO barbeiros(id, name, phone, specialty, cpf_iv, cpf_tag, cpf_encrypted, cpf_hash) VALUES
  (1, 'Andre Ribeiro', '(11) 96611-1001', 'Degrade', '100688765870b647b957f0b5', '301aefea88d407225f9583dd0ff36af0', '846df72ce4f41547ac448e', '62d0403939bdbbc4c784e4c9dcb413cb788271bc5c396be895e1a9d06780479b'),
  (2, 'Bruno Ferreira', '(11) 96622-2002', 'Barba e cabelo', 'ecec3c159d8ec7d1df835be2', '9d087c846066467c69e1b33bd06d1e4a', '3c8eb550d25720b9c4d35f', 'd69f2340975f2ccecbd531c394dffa13add2c970543b4a6d43f4e075e18a0444'),
  (3, 'Diego Martins', '(11) 96633-3003', 'Cortes classicos', '945e32152c44b0b8772da066', 'd5210229f5095f160b3b75d398926c1a', '4613824c5d0f4bf0b1683e', '2414bbee1db641db7f05e0d025db85334a7b15d7ceae1ed1f3bff681afc18cd6');

INSERT OR IGNORE INTO servicos(id, name, duration, price) VALUES
  (1, 'Corte tradicional', 40, 45.00),
  (2, 'Barba completa', 30, 35.00),
  (3, 'Corte + barba', 60, 70.00);

INSERT OR IGNORE INTO agendamentos(id, client_id, barber_id, service_id, starts_at, status, notes) VALUES
  (1, 1, 1, 1, '2026-10-28T09:00:00', 'Agendado', ''),
  (2, 2, 2, 2, '2026-10-28T10:00:00', 'Agendado', 'Preferencia por acabamento baixo'),
  (3, 3, 3, 3, '2026-10-29T14:30:00', 'Agendado', 'Atendimento de primeira visita');