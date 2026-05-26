require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// DB
const db = new sqlite3.Database('./database.sqlite');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24h
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware pour vérifier si user est connecté
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  db.get(`SELECT is_admin FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
    if (err || !row || !row.is_admin) return res.status(403).send('🔒 Accès admin refusé.');
    next();
  });
}

// Routes publiques
app.get('/', (req, res) => {
  db.all(`SELECT * FROM products`, (err, products) => {
    res.render('index', { user: req.session.user, products });
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send('❌ Identifiants invalides');
    }
    req.session.userId = user.id;
    req.session.user = { id: user.id, username: user.username, is_admin: user.is_admin };
    if (user.is_admin) return res.redirect('/admin');
    res.redirect('/account');
  });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)`, [username, hashedPassword], (err) => {
    if (err) return res.send('❌ Nom d\'utilisateur déjà pris');
    res.redirect('/login');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/account', requireAuth, (req, res) => {
  db.all(`SELECT p.name, p.price, pu.created_at, pu.status 
          FROM purchases pu 
          JOIN products p ON pu.product_id = p.id 
          WHERE pu.user_id = ?`, [req.session.userId], (err, purchases) => {
    res.render('account', { user: req.session.user, purchases });
  });
});

// Paiement Stripe
app.get('/checkout/:productId', requireAuth, (req, res) => {
  db.get(`SELECT * FROM products WHERE id = ?`, [req.params.productId], (err, product) => {
    if (!product) return res.status(404).send('Produit introuvable');
    res.render('checkout', { product });
  });
});

app.post('/create-checkout-session', requireAuth, async (req, res) => {
  const { productId } = req.body;
  db.get(`SELECT * FROM products WHERE id = ?`, [productId], async (err, product) => {
    if (!product) return res.status(404).json({ error: 'Produit introuvable' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: product.name },
          unit_amount: product.price,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `http://localhost:${PORT}/success?session_id={CHECKOUT_SESSION_ID}&product_id=${product.id}`,
      cancel_url: `http://localhost:${PORT}/cancel`,
    });

    db.run(`INSERT INTO purchases (user_id, product_id, stripe_session_id, status) VALUES (?, ?, ?, 'pending')`,
      [req.session.userId, product.id, session.id]);

    res.json({ id: session.id });
  });
});

app.get('/success', requireAuth, (req, res) => {
  const { session_id, product_id } = req.query;
  db.run(`UPDATE purchases SET status = 'paid' WHERE stripe_session_id = ?`, [session_id]);
  res.render('success');
});

app.get('/cancel', requireAuth, (req, res) => {
  res.render('cancel');
});

// ADMIN PANEL
app.get('/admin', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM products`, (err, products) => {
    db.all(`SELECT p.*, u.username FROM purchases pu 
            JOIN products p ON pu.product_id = p.id 
            JOIN users u ON pu.user_id = u.id 
            WHERE pu.status = 'paid'`, (err, purchases) => {
      res.render('admin', { products, purchases });
    });
  });
});

app.post('/admin/products/add', requireAdmin, (req, res) => {
  const { name, description, price, category, file_url } = req.body;
  db.run(`INSERT INTO products (name, description, price, category, file_url) VALUES (?, ?, ?, ?, ?)`,
    [name, description, parseInt(price), category, file_url], () => {
    res.redirect('/admin');
  });
});

app.post('/admin/products/delete/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], () => {
    res.redirect('/admin');
  });
});

app.listen(PORT, () => {
  console.log(`🔥 Serveur lancé sur http://localhost:${PORT}`);
  console.log(`👑 Admin : Kalinux / azertydox1234`);
});