const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  // Table users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
  )`);

  // Table products (cheats)
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price INTEGER,
    category TEXT,
    file_url TEXT
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

  // Création du compte admin (Kalinux / azertydox1234)
  const hashedPassword = bcrypt.hashSync('azertydox1234', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, 1)`, ['Kalinux', hashedPassword]);

  // Ajout de produits par défaut
  db.run(`INSERT OR IGNORE INTO products (id, name, description, price, category, file_url) VALUES 
    (1, 'AIM GOD++', 'Aimbot magnétique + triggerbot + no recoil', 2499, 'FPS', '/downloads/aimgod.exe'),
    (2, 'ESP Vision Pro', 'Wallhack + boxes santé + distance', 1999, 'FPS', '/downloads/esp.exe'),
    (3, 'Auto-Farm Godmode', 'Bot récolte XP et loot auto', 2999, 'RPG', '/downloads/autofarm.exe')
  `);
});

db.close();
console.log('✅ Base de données initialisée. Compte admin : Kalinux / azertydox1234');