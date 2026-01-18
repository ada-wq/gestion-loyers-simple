const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration de base
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Base de données SQLite
const db = new sqlite3.Database(':memory:');

// Initialisation de la base de données
db.serialize(() => {
    // Table des utilisateurs
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'associe',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Table des logements
    db.run(`
        CREATE TABLE IF NOT EXISTS logements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            adresse TEXT NOT NULL,
            locataire TEXT NOT NULL,
            loyer REAL NOT NULL,
            date_debut TEXT NOT NULL,
            mois_payes INTEGER DEFAULT 0,
            observations TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    `);
    
    // Table des paramètres
    db.run(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    `);
    
    // Insertion de l'admin par défaut (sera écrasé par les variables d'environnement)
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    
    bcrypt.hash(adminPassword, 10, (err, hash) => {
        if (err) {
            console.error('Erreur de hachage:', err);
            return;
        }
        
        db.run(
            'INSERT OR REPLACE INTO users (email, password, role) VALUES (?, ?, ?)',
            [adminEmail, hash, 'gerant'],
            (err) => {
                if (err && !err.message.includes('UNIQUE constraint failed')) {
                    console.error('Erreur insertion admin:', err);
                }
            }
        );
    });
    
    // Paramètres par défaut
    db.run(`
        INSERT OR REPLACE INTO settings (key, value) VALUES 
        ('jours_rappel', '7'),
        ('email_notifications', ''),
        ('rappel_active', 'true')
    `);
});

// Middleware d'authentification
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Non authentifié' });
    }
    next();
}

function requireGerant(req, res, next) {
    if (!req.session.userId || req.session.role !== 'gerant') {
        return res.status(403).json({ error: 'Accès réservé au gérant' });
    }
    next();
}

// Routes API

// Connexion
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }
        
        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) {
                return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
            }
            
            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.role = user.role;
            
            res.json({
                success: true,
                user: {
                    email: user.email,
                    role: user.role
                }
            });
        });
    });
});

// Déconnexion
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Vérifier la session
app.get('/api/session', (req, res) => {
    if (req.session.userId) {
        res.json({
            authenticated: true,
            user: {
                email: req.session.email,
                role: req.session.role
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

// CRUD Logements
app.get('/api/logements', requireAuth, (req, res) => {
    const userId = req.session.userId;
    const role = req.session.role;
    
    let query = 'SELECT * FROM logements';
    let params = [];
    
    if (role !== 'gerant') {
        query += ' WHERE created_by = ?';
        params.push(userId);
    }
    
    db.all(query, params, (err, logements) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        
        // Calculer les statuts
        const logementsAvecStatut = logements.map(logement => {
            const dateDebut = new Date(logement.date_debut);
            const dateFin = new Date(dateDebut);
            dateFin.setMonth(dateFin.getMonth() + logement.mois_payes);
            
            const aujourdhui = new Date();
            const diffJours = Math.ceil((dateFin - aujourdhui) / (1000 * 60 * 60 * 24));
            
            let statut = '✅ À jour';
            if (diffJours < 0) {
                statut = '❌ En retard';
            } else if (diffJours <= 7) {
                statut = '⚠️ Bientôt à échéance';
            }
            
            return {
                ...logement,
                date_fin: dateFin.toISOString().split('T')[0],
                statut,
                jours_restants: diffJours
            };
        });
        
        res.json(logementsAvecStatut);
    });
});

app.post('/api/logements', requireAuth, (req, res) => {
    const { nom, adresse, locataire, loyer, date_debut, mois_payes, observations } = req.body;
    const userId = req.session.userId;
    
    db.run(
        `INSERT INTO logements 
         (nom, adresse, locataire, loyer, date_debut, mois_payes, observations, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [nom, adresse, locataire, loyer, date_debut, mois_payes || 0, observations || '', userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Erreur création logement' });
            }
            
            res.json({
                success: true,
                id: this.lastID
            });
        }
    );
});

app.put('/api/logements/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const { nom, adresse, locataire, loyer, date_debut, mois_payes, observations } = req.body;
    const userId = req.session.userId;
    const role = req.session.role;
    
    // Vérifier les permissions
    let query = 'SELECT * FROM logements WHERE id = ?';
    let params = [id];
    
    if (role !== 'gerant') {
        query += ' AND created_by = ?';
        params.push(userId);
    }
    
    db.get(query, params, (err, logement) => {
        if (err || !logement) {
            return res.status(404).json({ error: 'Logement non trouvé ou accès interdit' });
        }
        
        // Mettre à jour
        db.run(
            `UPDATE logements SET 
             nom = ?, adresse = ?, locataire = ?, loyer = ?, 
             date_debut = ?, mois_payes = ?, observations = ? 
             WHERE id = ?`,
            [nom, adresse, locataire, loyer, date_debut, mois_payes, observations || '', id],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Erreur mise à jour' });
                }
                res.json({ success: true });
            }
        );
    });
});

app.delete('/api/logements/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const userId = req.session.userId;
    const role = req.session.role;
    
    let query = 'DELETE FROM logements WHERE id = ?';
    let params = [id];
    
    if (role !== 'gerant') {
        query += ' AND created_by = ?';
        params.push(userId);
    }
    
    db.run(query, params, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erreur suppression' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Logement non trouvé ou accès interdit' });
        }
        
        res.json({ success: true });
    });
});

// Statistiques
app.get('/api/statistiques', requireAuth, (req, res) => {
    const userId = req.session.userId;
    const role = req.session.role;
    
    let query = 'SELECT * FROM logements';
    let params = [];
    
    if (role !== 'gerant') {
        query += ' WHERE created_by = ?';
        params.push(userId);
    }
    
    db.all(query, params, (err, logements) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        
        let totalLoyer = 0;
        let bientotEcheance = 0;
        let enRetard = 0;
        
        logements.forEach(logement => {
            totalLoyer += logement.loyer;
            
            const dateDebut = new Date(logement.date_debut);
            const dateFin = new Date(dateDebut);
            dateFin.setMonth(dateFin.getMonth() + logement.mois_payes);
            
            const aujourdhui = new Date();
            const diffJours = Math.ceil((dateFin - aujourdhui) / (1000 * 60 * 60 * 24));
            
            if (diffJours < 0) {
                enRetard++;
            } else if (diffJours <= 7) {
                bientotEcheance++;
            }
        });
        
        res.json({
            total_logements: logements.length,
            total_loyer: totalLoyer,
            bientot_echeance: bientotEcheance,
            en_retard: enRetard
        });
    });
});

// Paramètres
app.get('/api/parametres', requireGerant, (req, res) => {
    db.all('SELECT * FROM settings', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        
        const settings = {};
        rows.forEach(row => {
            settings[row.key] = row.value;
        });
        
        res.json(settings);
    });
});

app.put('/api/parametres', requireGerant, (req, res) => {
    const { jours_rappel, email_notifications, rappel_active } = req.body;
    
    db.run(
        'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?), (?, ?), (?, ?)',
        ['jours_rappel', jours_rappel, 'email_notifications', email_notifications, 'rappel_active', rappel_active],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Erreur mise à jour' });
            }
            res.json({ success: true });
        }
    );
});

// Gestion des associés (seulement pour le gérant)
app.get('/api/associes', requireGerant, (req, res) => {
    db.all('SELECT id, email, role, created_at FROM users WHERE role = ?', ['associe'], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        res.json(users);
    });
});

app.post('/api/associes', requireGerant, (req, res) => {
    const { email, password } = req.body;
    
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Erreur de hachage' });
        }
        
        db.run(
            'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
            [email, hash, 'associe'],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Email déjà utilisé' });
                }
                
                res.json({
                    success: true,
                    id: this.lastID
                });
            }
        );
    });
});

app.delete('/api/associes/:id', requireGerant, (req, res) => {
    const { id } = req.params;
    
    db.run('DELETE FROM users WHERE id = ? AND role = ?', [id, 'associe'], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erreur suppression' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Associé non trouvé' });
        }
        
        res.json({ success: true });
    });
});

// Route pour servir l'interface
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Démarrer le serveur
app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});