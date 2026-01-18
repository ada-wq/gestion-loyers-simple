import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Servir le fichier HTML
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// API pour obtenir les identifiants admin (depuis les variables d'environnement)
app.get('/api/config', (req, res) => {
  res.json({
    adminEmail: process.env.ADMIN_EMAIL || 'admin@gestion-loyers.fr',
    adminPassword: process.env.ADMIN_PASSWORD || 'Admin123!'
  });
});

app.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
  console.log(`📧 Admin email: ${process.env.ADMIN_EMAIL || 'admin@gestion-loyers.fr'}`);
});