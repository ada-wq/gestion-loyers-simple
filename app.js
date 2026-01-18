const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { format, addMonths, differenceInDays } = require('date-fns');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_cfa_2026";

// Middleware CORS pour Render
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

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
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run(
        "INSERT INTO users (email,password,role) VALUES (?,?,?)",
        ["admin@example.com", hashedPassword, "admin"]
      );
      console.log("Compte admin créé : admin@example.com / admin123");
    }
  });

  db.get("SELECT COUNT(*) AS c FROM settings", (_, r) => {
    if (r.c === 0) {
      db.run("INSERT INTO settings (id) VALUES (1)");
    }
  });
});

// AUTH middleware
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
  console.log("Tentative de connexion pour:", email);
  
  db.get("SELECT * FROM users WHERE email=?", [email], (err, user) => {
    if (err) {
      console.error("Erreur DB:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    if (!user) {
      console.log("Utilisateur non trouvé:", email);
      return res.status(401).json({ error: "Identifiants invalides" });
    }
    
    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) {
      console.log("Mot de passe incorrect pour:", email);
      return res.status(401).json({ error: "Identifiants invalides" });
    }
    
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
    console.log("Connexion réussie pour:", email);
    res.json({ token, user: { email: user.email, role: user.role } });
  });
});

// DASHBOARD stats
app.get('/api/dashboard/stats', auth, (_, res) => {
  db.all("SELECT * FROM properties", [], (err, rows) => {
    if (err) {
      console.error("Erreur DB:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    let total = 0, soon = 0, late = 0;
    const today = new Date();

    rows.forEach(p => {
      total += p.monthly_rent || 0;
      const end = addMonths(new Date(p.start_date), p.months_paid || 0);
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
  db.all("SELECT * FROM properties", [], (err, rows) => {
    if (err) {
      console.error("Erreur DB:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    res.json(rows.map(p => {
      const end = addMonths(new Date(p.start_date), p.months_paid || 0);
      const d = differenceInDays(end, today);
      let status = "up-to-date";
      if (d < 0) status = "late";
      else if (d <= 30) status = "soon-due";
      
      return {
        ...p,
        end_date: format(end, "yyyy-MM-dd"),
        status: status
      };
    }));
  });
});

// CREATE property
app.post('/api/properties', auth, (req, res) => {
  const p = req.body;
  console.log("Création propriété:", p.name);
  
  db.run(
    `INSERT INTO properties 
     (name, address, tenant_name, monthly_rent, start_date, months_paid, notes, user_id)
     VALUES (?,?,?,?,?,?,?,1)`,
    [p.name, p.address, p.tenant_name, p.monthly_rent, p.start_date, p.months_paid || 0, p.notes],
    function(err) {
      if (err) {
        console.error("Erreur création:", err);
        return res.status(500).json({ error: "Erreur création" });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// PAYMENT
app.post('/api/properties/:id/payment', auth, (req, res) => {
  const months = parseInt(req.body.months) || 1;
  console.log(`Paiement ${months} mois pour propriété ${req.params.id}`);
  
  db.run(
    "UPDATE properties SET months_paid = months_paid + ? WHERE id=?",
    [months, req.params.id],
    (err) => {
      if (err) {
        console.error("Erreur paiement:", err);
        return res.status(500).json({ error: "Erreur mise à jour" });
      }
      res.json({ success: true });
    }
  );
});

// SETTINGS
app.get('/api/settings', auth, (_, res) => {
  db.get("SELECT * FROM settings WHERE id=1", (err, settings) => {
    if (err) {
      console.error("Erreur settings:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(settings || { reminder_days: 7, reminders_enabled: 1 });
  });
});

app.put('/api/settings', auth, (req, res) => {
  db.run(
    "UPDATE settings SET reminder_days=?, reminders_enabled=? WHERE id=1",
    [req.body.reminder_days, req.body.reminders_enabled],
    (err) => {
      if (err) {
        console.error("Erreur update settings:", err);
        return res.status(500).json({ error: "Erreur mise à jour" });
      }
      res.json({ success: true });
    }
  );
});

// TEST route
app.get('/api/test', (req, res) => {
  res.json({ message: "API fonctionne!", timestamp: new Date().toISOString() });
});

// SPA route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Application prête sur http://localhost:${PORT}`);
  console.log(`JWT_SECRET configuré: ${JWT_SECRET ? "OUI" : "NON"}`);
});