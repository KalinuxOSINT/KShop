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
  // Table users (déjà existante)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0,
    rank TEXT DEFAULT 'user',
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '/default-avatar.png',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Table posts (fil d'actualité)
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Table messages (messagerie privée)
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    content TEXT,
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`);

  // Migration: ajout des colonnes bio/avatar si absentes
  db.run(`ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT '/default-avatar.png'`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP`, (err) => {});

  // Création du compte admin principal
  const adminPassword = bcrypt.hashSync('azertydox1234', 10);
  db.run(`INSERT OR REPLACE INTO users (id, username, password, is_admin, rank) VALUES (1, 'Kalinux', ?, 1, 'admin')`, [adminPassword], (err) => {
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

// Middleware d'authentification
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

// ========== ROUTES PUBLIQUES ==========
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
    res.redirect('/');
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

// ========== FIL D'ACTUALITÉ (accueil) ==========
app.get('/', requireAuth, (req, res) => {
  db.all(`
    SELECT posts.*, users.username, users.avatar, users.rank 
    FROM posts 
    JOIN users ON posts.user_id = users.id 
    ORDER BY posts.created_at DESC
  `, [], (err, posts) => {
    if (err) posts = [];
    res.render('index', { user: req.session.user, posts });
  });
});

app.post('/api/post', requireAuth, (req, res) => {
  const { content } = req.body;
  if (!content || content.length > 500) return res.status(400).json({ error: 'Message trop long ou vide' });
  db.run(`INSERT INTO posts (user_id, content) VALUES (?, ?)`, [req.session.userId, content], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== MESSAGERIE PRIVÉE ==========
app.get('/messages', requireAuth, (req, res) => {
  // Liste des conversations (dernier message échangé)
  db.all(`
    SELECT 
      u.id, u.username, u.avatar, u.rank,
      (SELECT content FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY created_at DESC LIMIT 1) as last_date,
      (SELECT COUNT(*) FROM messages WHERE sender_id = u.id AND receiver_id = ? AND is_read = 0) as unread
    FROM users u
    WHERE u.id != ?
    ORDER BY last_date DESC
  `, [req.session.userId, req.session.userId, req.session.userId, req.session.userId, req.session.userId, req.session.userId], (err, conversations) => {
    if (err) conversations = [];
    res.render('messages', { user: req.session.user, conversations });
  });
});

app.get('/api/messages/:userId', requireAuth, (req, res) => {
  const otherId = parseInt(req.params.userId);
  db.all(`
    SELECT messages.*, users.username, users.avatar 
    FROM messages 
    JOIN users ON messages.sender_id = users.id
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at ASC
  `, [req.session.userId, otherId, otherId, req.session.userId], (err, messages) => {
    if (err) return res.status(500).json({ error: err.message });
    // Marquer comme lus
    db.run(`UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?`, [otherId, req.session.userId]);
    res.json(messages);
  });
});

app.post('/api/messages/send', requireAuth, (req, res) => {
  const { receiver_id, content } = req.body;
  if (!content || content.length > 1000) return res.status(400).json({ error: 'Message trop long' });
  db.run(`INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)`, [req.session.userId, receiver_id, content], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== PROFIL UTILISATEUR ==========
app.get('/profile/:id', requireAuth, (req, res) => {
  const targetId = parseInt(req.params.id);
  db.get(`SELECT id, username, bio, avatar, rank, created_at FROM users WHERE id = ?`, [targetId], (err, targetUser) => {
    if (!targetUser) return res.status(404).send('Utilisateur non trouvé');
    db.all(`SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE user_id = ? ORDER BY created_at DESC`, [targetId], (err, posts) => {
      res.render('profile', { user: req.session.user, targetUser, posts: posts || [] });
    });
  });
});

app.post('/api/profile/bio', requireAuth, (req, res) => {
  const { bio } = req.body;
  if (bio.length > 300) return res.status(400).json({ error: 'Bio trop longue' });
  db.run(`UPDATE users SET bio = ? WHERE id = ?`, [bio, req.session.userId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== ADMIN : GESTION DES UTILISATEURS ==========
app.get('/admin/users', requireAdmin, (req, res) => {
  res.render('admin-users');
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, username, is_admin, rank, bio, created_at FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const users = rows.map(u => ({
      id: u.id,
      username: u.username,
      rank: u.is_admin === 1 ? 'admin' : (u.rank || 'user'),
      bio: u.bio,
      created_at: u.created_at
    }));
    res.json(users);
  });
});

app.post('/api/admin/users/rank', requireAdmin, (req, res) => {
  const { userId, rank } = req.body;
  const validRanks = ['user', 'vip', 'premium', 'tester', 'banned', 'admin'];
  if (!validRanks.includes(rank)) return res.status(400).json({ error: 'Rang invalide' });
  const isAdmin = (rank === 'admin') ? 1 : 0;
  db.run(`UPDATE users SET is_admin = ?, rank = ? WHERE id = ?`, [isAdmin, rank, userId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.post('/api/admin/users/delete', requireAdmin, (req, res) => {
  const { userId } = req.body;
  if (userId === req.session.userId) return res.status(400).json({ error: "Tu ne peux pas te supprimer" });
  db.run(`DELETE FROM users WHERE id = ?`, [userId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== DÉMARRAGE ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ KaliNet lancé sur http://0.0.0.0:${PORT}`);
  console.log(`👑 Admin: Kalinux / azertydox1234`);
});
