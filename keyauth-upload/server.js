const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// ---- Config (troque depois) ----
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

let db; // instância do banco

// ---- Helpers de DB (sql.js não tem prepare direto como better-sqlite3) ----
function run(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    stmt.step();
    stmt.free();
    saveDb();
}
function get(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    let row = null;
    if (stmt.step()) row = stmt.getAsObject();
    stmt.free();
    return row;
}
function all(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
}
function saveDb() {
    const data = db.export();
    fs.writeFileSync('./data/keys.db', Buffer.from(data));
}

// ---- Inicialização ----
async function start() {
    if (!fs.existsSync('./data')) fs.mkdirSync('./data');

    const SQL = await initSqlJs();
    if (fs.existsSync('./data/keys.db')) {
        const buf = fs.readFileSync('./data/keys.db');
        db = new SQL.Database(buf);
    } else {
        db = new SQL.Database();
    }

    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            key           TEXT UNIQUE NOT NULL,
            plan          TEXT NOT NULL DEFAULT 'STD',
            duration_days INTEGER NOT NULL DEFAULT 30,
            hwid          TEXT,
            created_at    INTEGER NOT NULL,
            activated_at  INTEGER,
            expires_at    INTEGER,
            status        TEXT NOT NULL DEFAULT 'unused',
            note          TEXT
        );
    `);
    saveDb();

    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));

    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 20,
        message: { error: 'Muitas tentativas. Tente em 15 min.' }
    });

    function generateKey(plan = 'STD') {
        const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
        return `${plan}-${seg()}${seg()}-${seg()}${seg()}-${seg()}${seg()}`;
    }

    function authAdmin(req, res, next) {
        const header = req.headers.authorization || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Token ausente' });
        try {
            req.admin = jwt.verify(token, JWT_SECRET);
            next();
        } catch {
            return res.status(401).json({ error: 'Token inválido' });
        }
    }

    // ---- LOGIN ----
    app.post('/api/admin/login', loginLimiter, (req, res) => {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Campos obrigatórios' });

        if (username !== ADMIN_USER || password !== ADMIN_PASS)
            return res.status(401).json({ error: 'Credenciais inválidas' });

        const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token });
    });

    // ---- GERAR ----
    app.post('/api/admin/generate', authAdmin, (req, res) => {
        const { quantity = 1, plan = 'STD', duration_days = 30, note = '' } = req.body;

        if (quantity < 1 || quantity > 500)
            return res.status(400).json({ error: 'Quantidade entre 1 e 500' });

        const now = Date.now();
        const generated = [];

        for (let i = 0; i < quantity; i++) {
            let key, attempts = 0;
            do {
                key = generateKey(plan.toUpperCase().slice(0, 4));
                attempts++;
                if (attempts > 10) return res.status(500).json({ error: 'Falha ao gerar key única' });
            } while (get('SELECT 1 FROM licenses WHERE key = ?', [key]));

            run(`INSERT INTO licenses (key, plan, duration_days, created_at, status, note)
                 VALUES (?, ?, ?, ?, 'unused', ?)`,
                [key, plan, duration_days, now, note]);
            generated.push(key);
        }

        res.json({ count: generated.length, keys: generated });
    });

    // ---- LISTAR ----
    app.get('/api/admin/keys', authAdmin, (req, res) => {
        const { status, search, limit = 100, offset = 0 } = req.query;
        let sql = 'SELECT * FROM licenses WHERE 1=1';
        const params = [];

        if (status) { sql += ' AND status = ?'; params.push(status); }
        if (search) { sql += ' AND key LIKE ?'; params.push(`%${search}%`); }

        sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(Number(limit), Number(offset));

        const rows = all(sql, params);
        const total = get('SELECT COUNT(*) as c FROM licenses').c;
        res.json({ total, rows });
    });

    // ---- REVOGAR / RESET / DELETE ----
    app.post('/api/admin/revoke', authAdmin, (req, res) => {
        const row = get('SELECT * FROM licenses WHERE key = ?', [req.body.key]);
        if (!row) return res.status(404).json({ error: 'Key não encontrada' });
        run(`UPDATE licenses SET status = 'revoked' WHERE key = ?`, [req.body.key]);
        res.json({ ok: true });
    });

    app.post('/api/admin/reset', authAdmin, (req, res) => {
        const row = get('SELECT * FROM licenses WHERE key = ?', [req.body.key]);
        if (!row) return res.status(404).json({ error: 'Key não encontrada' });
        run(`UPDATE licenses SET status='unused', hwid=NULL, activated_at=NULL, expires_at=NULL WHERE key = ?`,
            [req.body.key]);
        res.json({ ok: true });
    });

    app.delete('/api/admin/delete/:key', authAdmin, (req, res) => {
        const row = get('SELECT * FROM licenses WHERE key = ?', [req.params.key]);
        if (!row) return res.status(404).json({ error: 'Key não encontrada' });
        run('DELETE FROM licenses WHERE key = ?', [req.params.key]);
        res.json({ ok: true });
    });

    // ---- AUTH (DLL) ----
    app.post('/api/auth', (req, res) => {
        const { key, hwid } = req.body;
        if (!key || !hwid)
            return res.status(400).json({ ok: false, error: 'key e hwid obrigatórios' });

        const row = get('SELECT * FROM licenses WHERE key = ?', [key]);
        if (!row) return res.status(404).json({ ok: false, error: 'Key inválida' });
        if (row.status === 'revoked') return res.status(403).json({ ok: false, error: 'Key revogada' });

        const now = Date.now();

        if (row.status === 'unused') {
            const expires = now + row.duration_days * 86400000;
            run(`UPDATE licenses SET status='active', hwid=?, activated_at=?, expires_at=? WHERE key=?`,
                [hwid, now, expires, key]);
            return res.json({ ok: true, plan: row.plan, expires_at: expires });
        }

        if (row.hwid !== hwid) return res.status(403).json({ ok: false, error: 'HWID não corresponde' });
        if (row.expires_at && now > row.expires_at) {
            run(`UPDATE licenses SET status='expired' WHERE key=?`, [key]);
            return res.status(403).json({ ok: false, error: 'Key expirada' });
        }

        res.json({ ok: true, plan: row.plan, expires_at: row.expires_at });
    });

    app.listen(PORT, () => {
        console.log('');
        console.log('  ================================');
        console.log('   KEYAUTH rodando!');
        console.log('   Abre: http://localhost:' + PORT);
        console.log('   Login: ' + ADMIN_USER + ' / ' + ADMIN_PASS);
        console.log('  ================================');
        console.log('');
    });
}

start().catch(err => {
    console.error('Falha ao iniciar:', err);
    process.exit(1);
});