const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { format, addMonths, differenceInDays } = require('date-fns');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-moi";

app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database('database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'admin'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    address TEXT,
    tenant_name TEXT,
    monthly_rent INTEGER,
    start_date DATE,
    months_paid INTEGER DEFAULT 0,
    notes TEXT,
    user_id INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY,
    reminder_days INTEGER DEFAULT 7,
    reminders_enabled INTEGER DEFAULT 1
  )`);

  db.get("SELECT COUNT(*) AS c FROM users", (_, r) => {
    if (r.c === 0) {
      db.run(
        "INSERT INTO users (email,password,role) VALUES (?,?,?)",
        ["admin@example.com", bcrypt.hashSync("admin123", 10), "admin"]
      );
    }
  });

  db.get("SELECT COUNT(*) AS c FROM settings", (_, r) => {
    if (r.c === 0) {
      db.run("INSERT INTO settings (id) VALUES (1)");
    }
  });
});

// AUTH
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (e, u) => {
    if (e) return res.sendStatus(403);
    req.user = u;
    next();
  });
}

// LOGIN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email=?", [email], (_, u) => {
    if (!u || !bcrypt.compareSync(password, u.password))
      return res.status(401).json({ error: "Identifiants invalides" });
    const token = jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ token });
  });
});

// DASHBOARD
app.get('/api/dashboard/stats', auth, (_, res) => {
  db.all("SELECT * FROM properties", [], (_, rows) => {
    let total = 0, soon = 0, late = 0;
    const today = new Date();

    rows.forEach(p => {
      total += p.monthly_rent;
      const end = addMonths(new Date(p.start_date), p.months_paid);
      const d = differenceInDays(end, today);
      if (d < 0) late++;
      else if (d <= 30) soon++;
    });

    res.json({
      totalProperties: rows.length,
      totalMonthlyRent: total,
      soonDue: soon,
      late
    });
  });
});

// PROPERTIES LIST
app.get('/api/properties', auth, (_, res) => {
  const today = new Date();
  db.all("SELECT * FROM properties", [], (_, rows) => {
    res.json(rows.map(p => {
      const end = addMonths(new Date(p.start_date), p.months_paid);
      const d = differenceInDays(end, today);
      return {
        ...p,
        end_date: format(end, "yyyy-MM-dd"),
        status: d < 0 ? "late" : d <= 30 ? "soon-due" : "up-to-date"
      };
    }));
  });
});

// CREATE / UPDATE
app.post('/api/properties', auth, (req, res) => {
  const p = req.body;
  db.run(
    `INSERT INTO properties 
     (name,address,tenant_name,monthly_rent,start_date,months_paid,notes,user_id)
     VALUES (?,?,?,?,?,?,?,1)`,
    [p.name, p.address, p.tenant_name, p.monthly_rent, p.start_date, p.months_paid, p.notes],
    () => res.json({ success: true })
  );
});

// PAYMENT
app.post('/api/properties/:id/payment', auth, (req, res) => {
  db.run(
    "UPDATE properties SET months_paid = months_paid + ? WHERE id=?",
    [req.body.months, req.params.id],
    () => res.json({ success: true })
  );
});

// SETTINGS
app.get('/api/settings', auth, (_, res) => {
  db.get("SELECT * FROM settings WHERE id=1", (_, s) => res.json(s));
});

app.put('/api/settings', auth, (req, res) => {
  db.run(
    "UPDATE settings SET reminder_days=?, reminders_enabled=? WHERE id=1",
    [req.body.reminder_days, req.body.reminders_enabled],
    () => res.json({ success: true })
  );
});

// SPA
app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log("🚀 Application prête sur Render");
});
