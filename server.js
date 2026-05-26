const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Utilisateurs fictifs (pour test)
const users = [
  { username: 'Kalinux', password: bcrypt.hashSync('azertydox1234', 10), is_admin: true }
];

// Routes
app.get('/', (req, res) => {
  res.send(`
    <h1>🔐 Bienvenue sur KalinuxShop</h1>
    ${req.session.user ? `<p>Connecté en tant que <strong>${req.session.user.username}</strong> | <a href="/logout">Déconnexion</a></p>` : '<a href="/login">Connexion</a>'}
    ${req.session.user && req.session.user.is_admin ? '<p><a href="/admin">📁 Panel Admin</a></p>' : ''}
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <form method="post">
      <input name="username" placeholder="Nom d'utilisateur" required><br>
      <input type="password" name="password" placeholder="Mot de passe" required><br>
      <button type="submit">Se connecter</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = { username: user.username, is_admin: user.is_admin };
    return res.redirect('/');
  }
  res.send('❌ Identifiants invalides. <a href="/login">Réessayer</a>');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/admin', (req, res) => {
  if (!req.session.user || !req.session.user.is_admin) return res.status(403).send('⛔ Accès refusé');
  res.send('<h1>👑 Panel Admin</h1><p>Bienvenue, maître. Les cheats sont prêts.</p><a href="/">Retour</a>');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Serveur admin fonctionnel sur http://0.0.0.0:${PORT}`);
  console.log(`👑 Admin : Kalinux / azertydox1234`);
});
