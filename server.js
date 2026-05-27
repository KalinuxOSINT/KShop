require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// ========== BASE DE DONNÉES ==========
const db = new sqlite3.Database('./database.sqlite');

// Création des tables et de l'admin en synchrone
db.serialize(() => {
  // Table users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
  )`);

  // Table products
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price INTEGER,
    category TEXT
  )`);

  // Ajout des produits par défaut
  db.get(`SELECT COUNT(*) as count FROM products`, (err, row) => {
    if (!err && row && row.count === 0) {
      db.run(`INSERT INTO products (name, description, price, category) VALUES 
        ('AIM GOD++', 'Aimbot + triggerbot + no recoil', 2499, 'FPS'),
        ('ESP Vision Pro', 'Wallhack + boxes + distance', 1999, 'FPS'),
        ('Auto-Farm Godmode', 'XP et loot automatique', 2999, 'RPG')
      `);
    }
  });

  // Création admin - méthode plus fiable
  const adminPassword = bcrypt.hashSync('azertydox1234', 10);
  db.run(`INSERT OR REPLACE INTO users (id, username, password, is_admin) VALUES (1, 'Kalinux', ?, 1)`, [adminPassword], (err) => {
    if (err) console.error("Erreur admin:", err);
    else console.log("✅ Admin Kalinux prêt");
  });
});

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Fonctions middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  db.get(`SELECT is_admin FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
    if (err || !row || !row.is_admin) return res.status(403).send('🔒 Accès admin refusé');
    next();
  });
}

// ========== ROUTES ==========
app.get('/', (req, res) => {
  db.all(`SELECT * FROM products`, (err, products) => {
    res.render('index', { user: req.session.user, products: products || [] });
  });
});

app.get('/login', (req, res) => { res.render('login'); });
app.get('/register', (req, res) => { res.render('register'); });

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`Tentative de connexion: ${username}`);
  
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) {
      console.error("Erreur DB:", err);
      return res.send('❌ Erreur technique');
    }
    
    if (!user) {
      console.log(`Utilisateur non trouvé: ${username}`);
      return res.send('❌ Identifiants invalides. <a href="/login">Réessayer</a>');
    }
    
    console.log(`Utilisateur trouvé: ${user.username}, Hash: ${user.password}`);
    
    const match = await bcrypt.compare(password, user.password);
    console.log(`Comparaison mot de passe: ${match ? 'OK' : 'ÉCHEC'}`);
    
    if (!match) {
      return res.send('❌ Mot de passe incorrect. <a href="/login">Réessayer</a>');
    }
    
    // Succès !
    req.session.userId = user.id;
    req.session.user = { id: user.id, username: user.username, is_admin: user.is_admin };
    console.log(`Connexion réussie pour ${username}`);
    
    if (user.is_admin) {
      return res.redirect('/admin');
    }
    res.redirect('/account');
  });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)`, [username, hashedPassword], (err) => {
    if (err) return res.send('❌ Nom déjà pris. <a href="/register">Réessayer</a>');
    res.redirect('/login');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/account', requireAuth, (req, res) => {
  res.render('account', { user: req.session.user });
});

app.get('/admin', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM products`, (err, products) => {
    res.render('admin', { products: products || [] });
  });
});

app.post('/admin/products/add', requireAdmin, (req, res) => {
  const { name, description, price, category } = req.body;
  db.run(`INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)`,
    [name, description, parseInt(price), category], () => {
    res.redirect('/admin');
  });
});

app.post('/admin/products/delete/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], () => {
    res.redirect('/admin');
  });
});
// ROUTE DE SECOURS POUR CRÉER L'ADMIN
app.get('/create-admin', (req, res) => {
  const adminHash = bcrypt.hashSync('azertydox1234', 10);
  db.run(`DELETE FROM users WHERE username = 'Kalinux'`);
  db.run(`INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)`, ['Kalinux', adminHash], (err) => {
    if (err) return res.send('❌ Erreur: ' + err.message);
    res.send('✅ Admin créé avec succès ! Va te connecter avec <strong>Kalinux</strong> / <strong>azertydox1234</strong>');
  });
});
// ROUTE DE TEST POUR VOIR LES UTILISATEURS
app.get('/debug-users', (req, res) => {
  db.all(`SELECT id, username, is_admin FROM users`, [], (err, rows) => {
    if (err) return res.send('Erreur: ' + err.message);
    if (!rows || rows.length === 0) return res.send('❌ Aucun utilisateur dans la base de données');
    
    let html = '<h1>👥 Utilisateurs dans la BDD</h1><ul>';
    rows.forEach(row => {
      html += `<li>ID: ${row.id} - Username: ${row.username} - Admin: ${row.is_admin ? 'OUI' : 'NON'}</li>`;
    });
    html += '</ul><a href="/login">Retour au login</a>';
    res.send(html);
  });
});
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔥 Serveur sur http://0.0.0.0:${PORT}`);
  console.log(`👑 Admin: Kalinux / azertydox1234`);
});
