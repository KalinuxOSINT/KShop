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

db.serialize(() => {
  // Table users avec colonne rank
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0,
    rank TEXT DEFAULT 'user'
  )`);

  // Ajout colonne rank si elle n'existe pas (migration)
  db.run(`ALTER TABLE users ADD COLUMN rank TEXT DEFAULT 'user'`, (err) => {
    if (err && !err.message.includes('duplicate')) {
      // colonne existe déjà ou erreur mineure
    }
  });

  // Table products
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price INTEGER,
    category TEXT
  )`);

  // Table purchases
  db.run(`CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    stripe_session_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

  // Création admin - méthode fiable avec rang
  const adminPassword = bcrypt.hashSync('azertydox1234', 10);
  db.run(`INSERT OR REPLACE INTO users (id, username, password, is_admin, rank) VALUES (1, 'Kalinux', ?, 1, 'admin')`, [adminPassword], (err) => {
    if (err) console.error("Erreur admin:", err);
    else console.log("✅ Admin Kalinux prêt (rang: admin)");
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
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send('❌ Identifiants invalides. <a href="/login">Réessayer</a>');
    }
    req.session.userId = user.id;
    req.session.user = { id: user.id, username: user.username, is_admin: user.is_admin, rank: user.rank || 'user' };
    res.redirect(user.is_admin ? '/admin' : '/account');
  });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password, is_admin, rank) VALUES (?, ?, 0, 'user')`, [username, hashedPassword], (err) => {
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

// ========== ADMIN PANEL ==========
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

// ========== GESTION DES UTILISATEURS (admin only) ==========
app.get('/admin/users', requireAdmin, (req, res) => {
    res.render('admin-users');
});

// API : récupérer tous les utilisateurs
app.get('/api/admin/users', requireAdmin, (req, res) => {
    db.all(`SELECT id, username, is_admin, COALESCE(rank, 'user') as rank FROM users`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const users = rows.map(u => ({
            id: u.id,
            username: u.username,
            rank: u.is_admin === 1 ? 'admin' : (u.rank || 'user')
        }));
        res.json(users);
    });
});

// API : mettre à jour le rang d'un utilisateur
app.post('/api/admin/users/rank', requireAdmin, (req, res) => {
    const { userId, rank } = req.body;
    
    const validRanks = ['user', 'vip', 'premium', 'tester', 'banned', 'admin'];
    if (!validRanks.includes(rank)) {
        return res.status(400).json({ error: 'Rang invalide' });
    }
    
    const isAdmin = (rank === 'admin') ? 1 : 0;
    
    db.run(`UPDATE users SET is_admin = ?, rank = ? WHERE id = ?`, [isAdmin, rank, userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ success: true });
    });
});

// API : supprimer un utilisateur
app.post('/api/admin/users/delete', requireAdmin, (req, res) => {
    const { userId } = req.body;
    
    if (userId === req.session.userId) {
        return res.status(400).json({ error: "Tu ne peux pas te supprimer toi-même !" });
    }
    
    db.run(`DELETE FROM users WHERE id = ?`, [userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ success: true });
    });
});

// ========== DÉMARRAGE ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Serveur OK sur http://0.0.0.0:${PORT}`);
  console.log(`👑 Admin: Kalinux / azertydox1234 (rang: admin)`);
});
