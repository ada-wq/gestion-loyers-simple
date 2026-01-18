const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration simplifiée
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "admin123";

// Middleware
app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database('database.sqlite');

// Initialisation de la base de données
db.serialize(() => {
  // Table utilisateurs simplifiée
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    full_name TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Table logements
  db.run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT,
    tenant_name TEXT,
    monthly_rent INTEGER NOT NULL,
    start_date DATE NOT NULL,
    months_paid INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Vérifier si admin existe
  db.get("SELECT COUNT(*) AS c FROM users WHERE username = ?", [ADMIN_USERNAME], (err, row) => {
    if (row.c === 0) {
      db.run(
        "INSERT INTO users (username, password, full_name, is_admin) VALUES (?,?,?,?)",
        [ADMIN_USERNAME, ADMIN_PASSWORD, "Administrateur Principal", 1]
      );
      console.log("✅ Compte admin créé avec succès");
      console.log(`👤 Username: ${ADMIN_USERNAME}`);
      console.log(`🔑 Password: ${ADMIN_PASSWORD}`);
    }
  });
});

// Middleware d'authentification simple
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Accès non autorisé" });
  }

  const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
  const [username, password] = credentials.split(':');

  db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }
    req.user = user;
    next();
  });
}

// 🔐 AUTHENTIFICATION SIMPLE
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }
    
    res.json({
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        is_admin: user.is_admin
      }
    });
  });
});

// 📊 DASHBOARD
app.get('/api/dashboard', authenticate, (req, res) => {
  db.all("SELECT * FROM properties", [], (err, properties) => {
    if (err) {
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    const stats = {
      totalProperties: properties.length,
      totalMonthlyRent: properties.reduce((sum, p) => sum + (p.monthly_rent || 0), 0),
      properties: properties
    };
    
    res.json(stats);
  });
});

// 🏠 GESTION DES LOGEMENTS
app.get('/api/properties', authenticate, (req, res) => {
  db.all("SELECT * FROM properties ORDER BY created_at DESC", [], (err, properties) => {
    if (err) {
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(properties);
  });
});

// CRÉER UN LOGEMENT
app.post('/api/properties', authenticate, (req, res) => {
  const { name, address, tenant_name, monthly_rent, start_date, notes } = req.body;
  
  if (!name || !monthly_rent || !start_date) {
    return res.status(400).json({ error: "Nom, loyer et date de début sont obligatoires" });
  }
  
  db.run(
    `INSERT INTO properties (name, address, tenant_name, monthly_rent, start_date, notes)
     VALUES (?,?,?,?,?,?)`,
    [name, address, tenant_name, monthly_rent, start_date, notes],
    function(err) {
      if (err) {
        return res.status(500).json({ error: "Erreur création" });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ENREGISTRER UN PAIEMENT
app.post('/api/properties/:id/payment', authenticate, (req, res) => {
  const { months, notes } = req.body;
  const propertyId = req.params.id;
  
  db.run(
    `UPDATE properties 
     SET months_paid = months_paid + ?,
         notes = CASE WHEN notes IS NULL OR notes = '' THEN notes ELSE COALESCE(notes, '') || '\nPaiement: ' || ? END
     WHERE id = ?`,
    [months, notes, propertyId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: "Erreur mise à jour" });
      }
      res.json({ success: true });
    }
  );
});

// SUPPRIMER UN LOGEMENT
app.delete('/api/properties/:id', authenticate, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès réservé aux administrateurs" });
  }
  
  db.run("DELETE FROM properties WHERE id = ?", [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: "Erreur suppression" });
    }
    res.json({ success: true });
  });
});

// AJOUTER UN NOUVEL UTILISATEUR (Admin seulement)
app.post('/api/users', authenticate, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès réservé aux administrateurs" });
  }
  
  const { username, password, full_name, is_admin } = req.body;
  
  if (!username || !password || !full_name) {
    return res.status(400).json({ error: "Tous les champs sont obligatoires" });
  }
  
  db.run(
    `INSERT INTO users (username, password, full_name, is_admin)
     VALUES (?,?,?,?)`,
    [username, password, full_name, is_admin ? 1 : 0],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: "Ce nom d'utilisateur est déjà utilisé" });
        }
        return res.status(500).json({ error: "Erreur création" });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// LISTER LES UTILISATEURS
app.get('/api/users', authenticate, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Accès réservé aux administrateurs" });
  }
  
  db.all("SELECT id, username, full_name, is_admin, created_at FROM users ORDER BY created_at DESC", 
    (err, users) => {
      if (err) {
        return res.status(500).json({ error: "Erreur serveur" });
      }
      res.json(users);
    }
  );
});

// ROUTE SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Application Gestion Loyers démarrée sur le port ${PORT}`);
  console.log(`🔗 Accédez à: http://localhost:${PORT}`);
  console.log(`👤 Connectez-vous avec:`);
  console.log(`   Username: ${ADMIN_USERNAME}`);
  console.log(`   Password: ${ADMIN_PASSWORD}`);
});