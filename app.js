const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { format, addMonths, differenceInDays } = require('date-fns');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ IDENTIFIANTS ADMIN (à changer !)
const ADMIN_USER = {
  email: "admin@cfa.com",      // ← METTEZ VOTRE EMAIL
  password: "admin123",        // ← METTEZ VOTRE MOT DE PASSE
  name: "Administrateur"
};

app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database('database.sqlite');

// Initialisation
db.serialize(() => {
  // Table des logements
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

  // Table des paramètres
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY,
    reminder_days INTEGER DEFAULT 7,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Table des paiements (historique)
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    months INTEGER,
    amount INTEGER,
    payment_date DATE,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Initialiser les paramètres
  db.get("SELECT COUNT(*) as count FROM settings", (err, row) => {
    if (row.count === 0) {
      db.run("INSERT INTO settings (id, reminder_days) VALUES (1, 7)");
    }
  });
});

// 🟢 SIMPLE AUTHENTIFICATION SESSION
let adminSession = null;

// Middleware de vérification de session
function checkSession(req, res, next) {
  if (!adminSession || adminSession.expires < Date.now()) {
    return res.status(401).json({ error: "Session expirée" });
  }
  next();
}

// 🟢 CONNEXION SIMPLE
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Vérification simple
  if (email === ADMIN_USER.email && password === ADMIN_USER.password) {
    // Créer une session valide 24h
    adminSession = {
      email: ADMIN_USER.email,
      name: ADMIN_USER.name,
      expires: Date.now() + (24 * 60 * 60 * 1000) // 24h
    };
    
    res.json({
      success: true,
      user: {
        name: ADMIN_USER.name,
        email: ADMIN_USER.email
      }
    });
  } else {
    res.status(401).json({ error: "Identifiants incorrects" });
  }
});

// 🟢 DÉCONNEXION
app.post('/api/logout', (req, res) => {
  adminSession = null;
  res.json({ success: true });
});

// 🟢 VÉRIFIER SESSION
app.get('/api/check-session', (req, res) => {
  if (adminSession && adminSession.expires > Date.now()) {
    res.json({ 
      loggedIn: true, 
      user: { name: adminSession.name, email: adminSession.email } 
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// 📊 DASHBOARD
app.get('/api/dashboard', checkSession, (req, res) => {
  db.all("SELECT * FROM properties", [], (err, properties) => {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    const today = new Date();
    let stats = {
      totalProperties: 0,
      totalMonthlyRent: 0,
      soonDue: 0,
      late: 0,
      properties: []
    };
    
    properties.forEach(property => {
      stats.totalProperties++;
      stats.totalMonthlyRent += property.monthly_rent || 0;
      
      const endDate = addMonths(new Date(property.start_date), property.months_paid || 0);
      const daysRemaining = differenceInDays(endDate, today);
      
      let status = 'up-to-date';
      if (daysRemaining < 0) {
        status = 'late';
        stats.late++;
      } else if (daysRemaining <= 7) {
        status = 'soon-due';
        stats.soonDue++;
      }
      
      stats.properties.push({
        ...property,
        end_date: format(endDate, 'yyyy-MM-dd'),
        days_remaining: daysRemaining,
        status: status,
        need_attention: daysRemaining <= 7
      });
    });
    
    // Récupérer les paramètres de rappel
    db.get("SELECT reminder_days FROM settings WHERE id = 1", (_, settings) => {
      stats.reminderDays = settings?.reminder_days || 7;
      res.json(stats);
    });
  });
});

// 🏠 LOGEMENTS
app.get('/api/properties', checkSession, (req, res) => {
  db.all("SELECT * FROM properties ORDER BY created_at DESC", [], (err, properties) => {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    const today = new Date();
    const formattedProperties = properties.map(property => {
      const endDate = addMonths(new Date(property.start_date), property.months_paid || 0);
      const daysRemaining = differenceInDays(endDate, today);
      
      let status = 'up-to-date';
      if (daysRemaining < 0) {
        status = 'late';
      } else if (daysRemaining <= 7) {
        status = 'soon-due';
      }
      
      return {
        ...property,
        end_date: format(endDate, 'yyyy-MM-dd'),
        days_remaining: daysRemaining,
        status: status
      };
    });
    
    res.json(formattedProperties);
  });
});

// ➕ CRÉER UN LOGEMENT
app.post('/api/properties', checkSession, (req, res) => {
  const { name, address, tenant_name, monthly_rent, start_date, notes } = req.body;
  
  if (!name || !monthly_rent || !start_date) {
    return res.status(400).json({ error: "Nom, loyer et date de début sont requis" });
  }
  
  db.run(
    `INSERT INTO properties (name, address, tenant_name, monthly_rent, start_date, notes)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name, address || '', tenant_name || '', monthly_rent, start_date, notes || ''],
    function(err) {
      if (err) {
        console.error("Erreur création:", err);
        return res.status(500).json({ error: "Erreur création" });
      }
      
      res.json({ 
        success: true, 
        id: this.lastID,
        message: "Logement créé avec succès"
      });
    }
  );
});

// 💰 ENREGISTRER UN PAIEMENT
app.post('/api/properties/:id/pay', checkSession, (req, res) => {
  const propertyId = req.params.id;
  const { months, notes } = req.body;
  
  if (!months || months <= 0) {
    return res.status(400).json({ error: "Nombre de mois invalide" });
  }
  
  // 1. Mettre à jour le logement
  db.run(
    "UPDATE properties SET months_paid = months_paid + ? WHERE id = ?",
    [months, propertyId],
    function(err) {
      if (err) {
        console.error("Erreur paiement:", err);
        return res.status(500).json({ error: "Erreur paiement" });
      }
      
      // 2. Récupérer le loyer pour l'historique
      db.get("SELECT monthly_rent FROM properties WHERE id = ?", [propertyId], (err, property) => {
        if (property) {
          const amount = property.monthly_rent * months;
          
          // 3. Enregistrer dans l'historique
          db.run(
            `INSERT INTO payments (property_id, months, amount, payment_date, notes)
             VALUES (?, ?, ?, DATE('now'), ?)`,
            [propertyId, months, amount, notes || '']
          );
        }
        
        res.json({ 
          success: true,
          message: `Paiement de ${months} mois enregistré`
        });
      });
    }
  );
});

// ⚙️ PARAMÈTRES
app.get('/api/settings', checkSession, (req, res) => {
  db.get("SELECT * FROM settings WHERE id = 1", (err, settings) => {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(settings || { reminder_days: 7 });
  });
});

app.put('/api/settings', checkSession, (req, res) => {
  const { reminder_days } = req.body;
  
  db.run(
    "UPDATE settings SET reminder_days = ? WHERE id = 1",
    [reminder_days],
    function(err) {
      if (err) {
        console.error("Erreur:", err);
        return res.status(500).json({ error: "Erreur mise à jour" });
      }
      
      res.json({ 
        success: true,
        message: "Paramètres mis à jour"
      });
    }
  );
});

// 📅 RAPPELS
app.get('/api/reminders', checkSession, (req, res) => {
  db.get("SELECT reminder_days FROM settings WHERE id = 1", (err, settings) => {
    const reminderDays = settings?.reminder_days || 7;
    
    db.all(`
      SELECT p.*, 
             DATE(p.start_date, '+' || (p.months_paid * 30) || ' days') as end_date,
             julianday(DATE(p.start_date, '+' || (p.months_paid * 30) || ' days')) - julianday('now') as days_left
      FROM properties p
      WHERE days_left BETWEEN 1 AND ?
      ORDER BY days_left ASC
    `, [reminderDays], (err, reminders) => {
      if (err) {
        console.error("Erreur:", err);
        return res.status(500).json({ error: "Erreur serveur" });
      }
      
      res.json(reminders);
    });
  });
});

// 🗑️ SUPPRIMER UN LOGEMENT
app.delete('/api/properties/:id', checkSession, (req, res) => {
  const propertyId = req.params.id;
  
  db.run("DELETE FROM properties WHERE id = ?", [propertyId], function(err) {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur suppression" });
    }
    
    // Supprimer aussi les paiements associés
    db.run("DELETE FROM payments WHERE property_id = ?", [propertyId]);
    
    res.json({ 
      success: true,
      message: "Logement supprimé"
    });
  });
});

// 📊 HISTORIQUE DES PAIEMENTS
app.get('/api/payments', checkSession, (req, res) => {
  db.all(`
    SELECT p.*, pr.name as property_name, pr.tenant_name
    FROM payments p
    LEFT JOIN properties pr ON p.property_id = pr.id
    ORDER BY p.payment_date DESC
    LIMIT 50
  `, [], (err, payments) => {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(payments);
  });
});

// 📄 EXPORT DONNÉES
app.get('/api/export', checkSession, (req, res) => {
  db.all(`
    SELECT 
      p.id,
      p.name as logement,
      p.address,
      p.tenant_name as locataire,
      p.monthly_rent as loyer_mensuel,
      p.start_date as date_debut,
      p.months_paid as mois_payes,
      DATE(p.start_date, '+' || (p.months_paid * 30) || ' days') as prochaine_echeance,
      p.notes,
      p.created_at as date_ajout
    FROM properties p
    ORDER BY p.name
  `, [], (err, data) => {
    if (err) {
      console.error("Erreur:", err);
      return res.status(500).json({ error: "Erreur export" });
    }
    res.json(data);
  });
});

// ROUTE SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Application Gestion Loyers démarrée sur le port ${PORT}`);
  console.log(`🔐 Admin: ${ADMIN_USER.email}`);
  console.log(`🔑 Mot de passe: ${ADMIN_USER.password}`);
  console.log(`📧 Changez ces identifiants dans le fichier app.js !`);
});