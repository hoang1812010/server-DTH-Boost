import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 8080);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-now";
const JWT_SECRET = process.env.JWT_SECRET || "change-this-jwt-secret";
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 12);
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_DIR = process.env.DB_DIR || __dirname;
const db = new Database(path.join(DB_DIR, "dth-boost.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  display_code TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL UNIQUE,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  duration_hours INTEGER NOT NULL DEFAULT 720,
  max_devices INTEGER NOT NULL DEFAULT 1,
  activated_at TEXT,
  expires_at TEXT,
  bound_install_id TEXT,
  bound_device_hash TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activation_logs (
  id TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  install_id TEXT,
  device_hash TEXT,
  device_name TEXT,
  android_version TEXT,
  created_at TEXT NOT NULL
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: ALLOW_ORIGIN === "*" ? true : ALLOW_ORIGIN.split(",") }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const nowIso = () => new Date().toISOString();
const addHours = (dateIso, hours) => {
  const d = new Date(dateIso);
  d.setHours(d.getHours() + hours);
  return d.toISOString();
};
const normalizeKey = input => String(input || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
const sha256 = input => crypto.createHash("sha256").update(input).digest("hex");

function randomCode(groups = 4, groupLen = 4) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const out = [];
  for (let g = 0; g < groups; g += 1) {
    let chunk = "";
    for (let i = 0; i < groupLen; i += 1) {
      chunk += alphabet[crypto.randomInt(0, alphabet.length)];
    }
    out.push(chunk);
  }
  return out.join("-");
}

const signAdminToken = () => jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
const signSessionToken = key => {
  const ttlHours = Math.max(
    1,
    Math.min(
      SESSION_HOURS,
      Math.floor((new Date(key.expires_at).getTime() - Date.now()) / 3600000) || 1
    )
  );
  return jwt.sign(
    { role: "session", keyId: key.id, installId: key.bound_install_id, deviceHash: key.bound_device_hash },
    JWT_SECRET,
    { expiresIn: `${ttlHours}h` }
  );
};

function authAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, error: "Missing admin token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") return res.status(403).json({ ok: false, error: "Forbidden" });
    req.admin = payload;
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid admin token" });
  }
}

function logActivationEvent(keyId, eventType, body) {
  db.prepare(`
    INSERT INTO activation_logs (
      id, key_id, event_type, install_id, device_hash, device_name, android_version, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(),
    keyId,
    eventType,
    body.installId || null,
    body.bindingId || null,
    body.deviceName || null,
    body.androidVersion || null,
    nowIso()
  );
}

function makeLicenseResponse(keyRow) {
  return {
    ok: true,
    sessionToken: signSessionToken(keyRow),
    expiresAt: keyRow.expires_at,
    license: {
      keyId: keyRow.id,
      statusLabel: keyRow.status === "active" ? "Đang hoạt động" : keyRow.status,
      bindingLabel: keyRow.bound_install_id ? "Đã khóa theo thiết bị này" : "Chưa ràng buộc"
    }
  };
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "dth-boost-key-server", time: nowIso() });
});

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Sai tài khoản hoặc mật khẩu" });
  }
  return res.json({ ok: true, token: signAdminToken() });
});

app.get("/api/admin/keys", authAdmin, (_req, res) => {
  const rows = db.prepare(`
    SELECT id, display_code, note, status, duration_hours, max_devices,
           activated_at, expires_at, bound_install_id, last_seen_at, created_at
    FROM keys
    ORDER BY created_at DESC
  `).all();
  res.json({ ok: true, keys: rows });
});

app.post("/api/admin/keys", authAdmin, (req, res) => {
  const quantity = Math.max(1, Math.min(500, Number(req.body?.quantity || 1)));
  const durationHours = Math.max(1, Number(req.body?.durationHours || 24 * 30));
  const maxDevices = Math.max(1, Math.min(3, Number(req.body?.maxDevices || 1)));
  const note = String(req.body?.note || "").slice(0, 200);

  const created = [];
  const stmt = db.prepare(`
    INSERT INTO keys (
      id, display_code, key_hash, note, status, duration_hours, max_devices, created_at
    ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    for (let i = 0; i < quantity; i += 1) {
      let code = randomCode();
      while (db.prepare("SELECT 1 FROM keys WHERE display_code = ?").get(code)) {
        code = randomCode();
      }
      stmt.run(
        crypto.randomUUID(),
        code,
        sha256(normalizeKey(code)),
        note,
        durationHours,
        maxDevices,
        nowIso()
      );
      created.push(code);
    }
  });
  tx();
  res.json({ ok: true, created });
});

app.post("/api/admin/keys/:id/revoke", authAdmin, (req, res) => {
  const info = db.prepare("UPDATE keys SET status = 'revoked' WHERE id = ?").run(req.params.id);
  if (!info.changes) return res.status(404).json({ ok: false, error: "Không tìm thấy key" });
  return res.json({ ok: true });
});

app.post("/api/admin/keys/:id/extend", authAdmin, (req, res) => {
  const moreHours = Math.max(1, Number(req.body?.hours || 24));
  const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ ok: false, error: "Không tìm thấy key" });

  const base = row.expires_at && new Date(row.expires_at).getTime() > Date.now()
    ? row.expires_at
    : nowIso();
  const nextExpiry = addHours(base, moreHours);
  db.prepare("UPDATE keys SET expires_at = ? WHERE id = ?").run(nextExpiry, req.params.id);
  return res.json({ ok: true, expiresAt: nextExpiry });
});

function activateHandler(req, res) {
  const body = req.body || {};
  const normalized = normalizeKey(body.key);
  if (!normalized) return res.status(400).json({ ok: false, error: "Thiếu key" });

  const row = db.prepare("SELECT * FROM keys WHERE key_hash = ?").get(sha256(normalized));
  if (!row) return res.status(404).json({ ok: false, error: "Key không tồn tại" });
  if (row.status !== "active") return res.status(403).json({ ok: false, error: "Key đã bị khóa" });
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return res.status(403).json({ ok: false, error: "Key đã hết hạn" });
  }

  const installId = String(body.installId || "").trim();
  const bindingId = String(body.bindingId || "").trim();
  if (!installId || !bindingId) {
    return res.status(400).json({ ok: false, error: "Thiếu thông tin ràng buộc thiết bị" });
  }

  if (row.bound_install_id && row.bound_device_hash) {
    const sameDevice = row.bound_install_id === installId && row.bound_device_hash === bindingId;
    if (!sameDevice) {
      return res.status(409).json({ ok: false, error: "Key này đã được dùng trên thiết bị khác" });
    }
  } else {
    const activatedAt = nowIso();
    const expiresAt = addHours(activatedAt, row.duration_hours);
    db.prepare(`
      UPDATE keys
      SET activated_at = ?, expires_at = ?, bound_install_id = ?, bound_device_hash = ?, last_seen_at = ?
      WHERE id = ?
    `).run(activatedAt, expiresAt, installId, bindingId, nowIso(), row.id);
    logActivationEvent(row.id, "activate", body);
  }

  const updated = db.prepare("SELECT * FROM keys WHERE id = ?").get(row.id);
  db.prepare("UPDATE keys SET last_seen_at = ? WHERE id = ?").run(nowIso(), row.id);
  logActivationEvent(row.id, "refresh", body);
  return res.json(makeLicenseResponse(updated));
}

app.post("/api/activate", activateHandler);
app.post("/api/key/verify", activateHandler);

app.post("/api/session/refresh", (req, res) => {
  const { sessionToken, installId, bindingId } = req.body || {};
  if (!sessionToken) return res.status(400).json({ ok: false, error: "Thiếu session token" });

  let payload;
  try {
    payload = jwt.verify(sessionToken, JWT_SECRET);
  } catch {
    return res.status(401).json({ ok: false, error: "Session token không hợp lệ" });
  }

  if (payload.role !== "session") return res.status(403).json({ ok: false, error: "Sai loại token" });

  const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(payload.keyId);
  if (!row) return res.status(404).json({ ok: false, error: "Không tìm thấy key" });
  if (row.status !== "active") return res.status(403).json({ ok: false, error: "Key đã bị khóa" });
  if (!row.expires_at || new Date(row.expires_at).getTime() <= Date.now()) {
    return res.status(403).json({ ok: false, error: "Key đã hết hạn" });
  }
  if (row.bound_install_id !== installId || row.bound_device_hash !== bindingId) {
    return res.status(409).json({ ok: false, error: "Thiết bị không khớp với key đã kích hoạt" });
  }

  db.prepare("UPDATE keys SET last_seen_at = ? WHERE id = ?").run(nowIso(), row.id);
  return res.json(makeLicenseResponse(row));
});

const HOST = "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`DTH Boost key server listening on http://${HOST}:${PORT}`);
});
