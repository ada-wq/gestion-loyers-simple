const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { format, addMonths, differenceInDays } = require('date-fns');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_2026_prod";

// Configuration email
const emailConfig = {
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'test@example.com',
    pass: process.env.EMAIL_PASS || 'password'
  }
};

const transporter = nodemailer.createTransport(emailConfig);

// Middleware
app.use(express.json());
app.use(express.static('.'));

// Enable CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const db = new sqlite3.Database('database.sqlite');

// Initialisation de la base de données
db.serialize(() => {
  // Table utilisateurs
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    full_name TEXT,
    role TEXT DEFAULT 'associe',
    phone TEXT,
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
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Table paramètres
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY,
    reminder_days INTEGER DEFAULT 7,
    email_notifications INTEGER DEFAULT 1,
    app_notifications INTEGER DEFAULT 1,
    notification_email TEXT,
    timezone TEXT DEFAULT 'Africa/Abidjan',
    created_by INTEGER
  )`);

  // Table logs d'activité
  db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Créer un admin par défaut si aucun utilisateur
  db.get("SELECT COUNT(*) AS c FROM users", (err, r) => {
    if (err) {
      console.error("Erreur vérification users:", err);
      return;
    }
    
    if (r.c === 0) {
      const defaultPassword = process.env.ADMIN_PASSWORD || "admin123456";
      const hashedPassword = bcrypt.hashSync(defaultPassword, 10);
      const adminEmail = process.env.ADMIN_EMAIL || "admin@entreprise-cfa.com";
      
      db.run(
        "INSERT INTO users (email, password, full_name, role) VALUES (?,?,?,?)",
        [adminEmail, hashedPassword, "Administrateur Principal", "admin"],
        function(err) {
          if (err) {
            console.error("❌ Erreur création admin:", err);
          } else {
            console.log("✅ Compte admin créé avec succès");
            console.log("📧 Email:", adminEmail);
            console.log("🔑 Mot de passe:", defaultPassword);
            
            // Initialiser les paramètres
            db.run("INSERT OR IGNORE INTO settings (id, notification_email, created_by) VALUES (1, ?, 1)", 
                   [adminEmail], function(err) {
              if (err) console.error("❌ Erreur initialisation settings:", err);
            });
          }
        }
      );
    } else {
      console.log("✅ Base de données déjà initialisée");
    }
  });
});

// Middleware d'authentification
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token manquant" });
  
  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token manquant" });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error("Token verification error:", err);
      return res.status(403).json({ error: "Token invalide ou expiré" });
    }
    req.user = user;
    next();
  });
}

// Middleware admin seulement
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Accès réservé aux administrateurs" });
  }
  next();
}

// Log d'activité
function logActivity(userId, action, details) {
  db.run(
    "INSERT INTO activity_logs (user_id, action, details) VALUES (?,?,?)",
    [userId, action, details],
    (err) => {
      if (err) console.error("Erreur log activité:", err);
    }
  );
}

// 🔐 AUTHENTIFICATION
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Erreur DB login:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    if (!user) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }
    
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role, 
        name: user.full_name 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    logActivity(user.id, 'CONNEXION', `Connexion réussie`);
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        phone: user.phone
      }
    });
  });
});

// 📊 DASHBOARD
app.get('/api/dashboard', authenticate, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  
  let query = "SELECT * FROM properties";
  let params = [];
  
  if (role === 'associe') {
    query += " WHERE user_id = ?";
    params.push(userId);
  }
  
  db.all(query, params, (err, properties) => {
    if (err) {
      console.error("Erreur DB dashboard:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    const today = new Date();
    let stats = {
      totalProperties: properties.length,
      totalMonthlyRent: 0,
      soonDue: 0,
      late: 0,
      properties: []
    };
    
    properties.forEach(property => {
      const monthlyRent = property.monthly_rent || 0;
      stats.totalMonthlyRent += monthlyRent;
      
      const startDate = new Date(property.start_date);
      const endDate = addMonths(startDate, property.months_paid || 0);
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
        need_attention: daysRemaining <= 7 || daysRemaining < 0
      });
    });
    
    // Récupérer les paramètres
    db.get("SELECT reminder_days FROM settings WHERE id = 1", (err, settings) => {
      if (err) console.error("Erreur récupération settings:", err);
      stats.reminderDays = settings?.reminder_days || 7;
      res.json(stats);
    });
  });
});

// 🏠 GESTION DES LOGEMENTS
app.get('/api/properties', authenticate, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  
  let query = "SELECT * FROM properties";
  let params = [];
  
  if (role === 'associe') {
    query += " WHERE user_id = ? ORDER BY created_at DESC";
    params.push(userId);
  } else {
    query += " ORDER BY created_at DESC";
  }
  
  db.all(query, params, (err, properties) => {
    if (err) {
      console.error("Erreur DB properties:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    const today = new Date();
    const formattedProperties = properties.map(property => {
      const startDate = new Date(property.start_date);
      const endDate = addMonths(startDate, property.months_paid || 0);
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
        status: status,
        need_attention: daysRemaining <= 7 || daysRemaining < 0
      };
    });
    
    res.json(formattedProperties);
  });
});

// CRÉER UN LOGEMENT
app.post('/api/properties', authenticate, (req, res) => {
  const { name, address, tenant_name, monthly_rent, start_date, notes } = req.body;
  const userId = req.user.id;
  
  if (!name || !monthly_rent || !start_date) {
    return res.status(400).json({ error: "Nom, loyer et date de début sont obligatoires" });
  }
  
  db.run(
    `INSERT INTO properties 
     (name, address, tenant_name, monthly_rent, start_date, notes, user_id)
     VALUES (?,?,?,?,?,?,?)`,
    [name, address || '', tenant_name || '', monthly_rent, start_date, notes || '', userId],
    function(err) {
      if (err) {
        console.error("Erreur création logement:", err);
        return res.status(500).json({ error: "Erreur création du logement" });
      }
      
      logActivity(userId, 'CREATION_LOGEMENT', `Logement créé: ${name}`);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ENREGISTRER UN PAIEMENT
app.post('/api/properties/:id/payment', authenticate, (req, res) => {
  const { months, notes } = req.body;
  const propertyId = req.params.id;
  const userId = req.user.id;
  
  if (!months || months <= 0) {
    return res.status(400).json({ error: "Nombre de mois valide requis" });
  }
  
  db.run(
    `UPDATE properties 
     SET months_paid = months_paid + ?,
         notes = CASE WHEN notes IS NULL OR notes = '' THEN COALESCE(notes, '') 
                     ELSE COALESCE(notes, '') || '\n' || ? END
     WHERE id = ?`,
    [months, notes || '', propertyId],
    function(err) {
      if (err) {
        console.error("Erreur paiement:", err);
        return res.status(500).json({ error: "Erreur lors de l'enregistrement du paiement" });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: "Logement non trouvé" });
      }
      
      logActivity(userId, 'PAIEMENT', `${months} mois payés pour logement #${propertyId}`);
      
      // Vérifier si un rappel doit être envoyé
      checkAndSendReminders(propertyId);
      
      res.json({ success: true });
    }
  );
});

// RÉCUPÉRER UN LOGEMENT
app.get('/api/properties/:id', authenticate, (req, res) => {
  const propertyId = req.params.id;
  const userId = req.user.id;
  const role = req.user.role;
  
  let query = "SELECT * FROM properties WHERE id = ?";
  let params = [propertyId];
  
  if (role === 'associe') {
    query += " AND user_id = ?";
    params.push(userId);
  }
  
  db.get(query, params, (err, property) => {
    if (err) {
      console.error("Erreur récupération logement:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    
    if (!property) {
      return res.status(404).json({ error: "Logement non trouvé" });
    }
    
    // Calculer la date de fin
    const startDate = new Date(property.start_date);
    const endDate = addMonths(startDate, property.months_paid || 0);
    const today = new Date();
    const daysRemaining = differenceInDays(endDate, today);
    
    let status = 'up-to-date';
    if (daysRemaining < 0) {
      status = 'late';
    } else if (daysRemaining <= 7) {
      status = 'soon-due';
    }
    
    res.json({
      ...property,
      end_date: format(endDate, 'yyyy-MM-dd'),
      days_remaining: daysRemaining,
      status: status
    });
  });
});

// SUPPRIMER UN LOGEMENT (Admin seulement)
app.delete('/api/properties/:id', authenticate, adminOnly, (req, res) => {
  const propertyId = req.params.id;
  
  db.run("DELETE FROM properties WHERE id = ?", [propertyId], function(err) {
    if (err) {
      console.error("Erreur suppression logement:", err);
      return res.status(500).json({ error: "Erreur lors de la suppression" });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: "Logement non trouvé" });
    }
    
    logActivity(req.user.id, 'SUPPRESSION_LOGEMENT', `Logement #${propertyId} supprimé`);
    res.json({ success: true });
  });
});

// 👥 GESTION DES UTILISATEURS (Admin seulement)
app.get('/api/users', authenticate, adminOnly, (req, res) => {
  db.all("SELECT id, email, full_name, role, phone, created_at FROM users ORDER BY role, created_at DESC", 
    (err, users) => {
      if (err) {
        console.error("Erreur DB users:", err);
        return res.status(500).json({ error: "Erreur serveur" });
      }
      res.json(users);
    }
  );
});

// CRÉER UN UTILISATEUR
app.post('/api/users', authenticate, adminOnly, (req, res) => {
  const { email, full_name, role, phone, password } = req.body;
  
  if (!email || !full_name || !password) {
    return res.status(400).json({ error: "Email, nom et mot de passe sont obligatoires" });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  db.run(
    `INSERT INTO users (email, password, full_name, role, phone)
     VALUES (?,?,?,?,?)`,
    [email, hashedPassword, full_name, role || 'associe', phone || ''],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: "Cet email est déjà utilisé" });
        }
        console.error("Erreur création utilisateur:", err);
        return res.status(500).json({ error: "Erreur création utilisateur" });
      }
      
      logActivity(req.user.id, 'CREATION_UTILISATEUR', `Utilisateur créé: ${email}`);
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ⚙️ PARAMÈTRES
app.get('/api/settings', authenticate, (req, res) => {
  db.get("SELECT * FROM settings WHERE id = 1", (err, settings) => {
    if (err) {
      console.error("Erreur settings:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(settings || {});
  });
});

app.put('/api/settings', authenticate, adminOnly, (req, res) => {
  const { reminder_days, email_notifications, app_notifications, notification_email, timezone } = req.body;
  
  db.run(
    `INSERT OR REPLACE INTO settings 
     (id, reminder_days, email_notifications, app_notifications, notification_email, timezone, created_by)
     VALUES (1, ?, ?, ?, ?, ?, ?)`,
    [reminder_days || 7, email_notifications || 1, app_notifications || 1, 
     notification_email || '', timezone || 'Africa/Abidjan', req.user.id],
    (err) => {
      if (err) {
        console.error("Erreur update settings:", err);
        return res.status(500).json({ error: "Erreur mise à jour des paramètres" });
      }
      
      logActivity(req.user.id, 'MODIFICATION_PARAMETRES', 'Paramètres mis à jour');
      res.json({ success: true });
    }
  );
});

// 🔔 SYSTÈME DE RAPPELS
async function checkAndSendReminders(propertyId = null) {
  db.get("SELECT reminder_days, email_notifications, notification_email FROM settings WHERE id = 1", 
    async (err, settings) => {
      if (err || !settings || !settings.email_notifications || !settings.notification_email) {
        console.log("Rappels désactivés ou paramètres manquants");
        return;
      }
      
      const reminderDays = settings.reminder_days || 7;
      const notificationEmail = settings.notification_email;
      
      let query = "SELECT p.*, u.email as owner_email FROM properties p LEFT JOIN users u ON p.user_id = u.id";
      let params = [];
      
      if (propertyId) {
        query += " WHERE p.id = ?";
        params.push(propertyId);
      }
      
      db.all(query, params, async (err, properties) => {
        if (err) {
          console.error("Erreur rappels:", err);
          return;
        }
        
        const today = new Date();
        
        for (const property of properties) {
          const startDate = new Date(property.start_date);
          const endDate = addMonths(startDate, property.months_paid || 0);
          const daysRemaining = differenceInDays(endDate, today);
          
          if (daysRemaining > 0 && daysRemaining <= reminderDays) {
            await sendReminderEmail(property, endDate, daysRemaining, notificationEmail);
          }
        }
      });
    }
  );
}

async function sendReminderEmail(property, endDate, daysRemaining, toEmail) {
  const formattedDate = format(endDate, 'dd/MM/yyyy');
  
  const mailOptions = {
    from: emailConfig.auth.user,
    to: toEmail,
    subject: `🔔 Rappel: Logement "${property.name}" arrive à échéance`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">Rappel de paiement de loyer</h2>
        <p>Le logement suivant arrive bientôt à échéance :</p>
        
        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p><strong>🏠 Logement :</strong> ${property.name}</p>
          <p><strong>📌 Adresse :</strong> ${property.address || 'Non renseignée'}</p>
          <p><strong>👤 Locataire :</strong> ${property.tenant_name || 'Non renseigné'}</p>
          <p><strong>💰 Loyer mensuel :</strong> ${(property.monthly_rent || 0).toLocaleString()} FCFA</p>
          <p><strong>📅 Date de fin :</strong> ${formattedDate}</p>
          <p><strong>⏳ Jours restants :</strong> ${daysRemaining} jour(s)</p>
        </div>
        
        <p style="color: #dc2626; font-weight: bold;">
          ⚠️ Pensez à demander le paiement au locataire avant la date d'échéance.
        </p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
          <p style="color: #6b7280; font-size: 14px;">
            Ce message a été généré automatiquement par le système de gestion de loyers.
          </p>
        </div>
      </div>
    `
  };
  
  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email de rappel envoyé pour ${property.name}`);
  } catch (error) {
    console.error("❌ Erreur envoi email:", error);
  }
}

// Planifier les vérifications de rappels (toutes les heures)
setInterval(() => {
  checkAndSendReminders();
}, 3600000);

// 📝 ACTIVITÉS
app.get('/api/activity', authenticate, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  
  let query = `SELECT a.*, u.full_name, u.email 
               FROM activity_logs a 
               LEFT JOIN users u ON a.user_id = u.id`;
  let params = [];
  
  if (role === 'associe') {
    query += " WHERE a.user_id = ?";
    params.push(userId);
  }
  
  query += " ORDER BY a.created_at DESC LIMIT 50";
  
  db.all(query, params, (err, logs) => {
    if (err) {
      console.error("Erreur activités:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(logs);
  });
});

// 📈 RAPPORTS
app.get('/api/reports/monthly', authenticate, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  
  let query = `SELECT 
    strftime('%Y-%m', created_at) as month,
    COUNT(*) as properties_count,
    SUM(monthly_rent) as total_rent
    FROM properties`;
  let params = [];
  
  if (role === 'associe') {
    query += " WHERE user_id = ?";
    params.push(userId);
  }
  
  query += " GROUP BY strftime('%Y-%m', created_at) ORDER BY month DESC LIMIT 12";
  
  db.all(query, params, (err, report) => {
    if (err) {
      console.error("Erreur rapport:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(report || []);
  });
});

// ROUTE POUR MODIFIER SON PROFIL
app.put('/api/profile', authenticate, (req, res) => {
  const { full_name, phone, current_password, new_password } = req.body;
  const userId = req.user.id;
  
  // Vérifier si l'utilisateur existe
  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: "Utilisateur non trouvé" });
    }
    
    let updates = [];
    let params = [];
    
    if (full_name) {
      updates.push("full_name = ?");
      params.push(full_name);
    }
    
    if (phone !== undefined) {
      updates.push("phone = ?");
      params.push(phone || '');
    }
    
    // Gestion du changement de mot de passe
    if (current_password && new_password) {
      if (!bcrypt.compareSync(current_password, user.password)) {
        return res.status(400).json({ error: "Mot de passe actuel incorrect" });
      }
      
      const hashedNewPassword = bcrypt.hashSync(new_password, 10);
      updates.push("password = ?");
      params.push(hashedNewPassword);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: "Aucune modification à apporter" });
    }
    
    params.push(userId);
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    
    db.run(query, params, function(err) {
      if (err) {
        console.error("Erreur mise à jour profil:", err);
        return res.status(500).json({ error: "Erreur mise à jour du profil" });
      }
      
      logActivity(userId, 'MODIFICATION_PROFIL', 'Profil mis à jour');
      res.json({ success: true });
    });
  });
});

// ROUTE DE SANTÉ
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Gestion Loyers Pro API'
  });
});

// ROUTE SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Gestion des erreurs
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

app.listen(PORT, () => {
  console.log(`🚀 Application Gestion Loyers Pro démarrée sur le port ${PORT}`);
  console.log(`🔗 URL: http://localhost:${PORT}`);
  console.log(`📧 Email configuré: ${emailConfig.auth.user}`);
  console.log(`👤 Compte admin par défaut: admin@entreprise-cfa.com / admin123456`);
});