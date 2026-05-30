require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// ========== SUPABASE CLIENT (avec clé service_role) ==========
const supabase = createClient(
  process.env.SUPABASE_URL || 'https://zsoprszlbycbbcadnqyi.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inpzb3Byc3psYnljYmJjYWRucXlpIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MDEzOTY0OSwiZXhwIjoyMDk1NzE1NjQ5fQ.PLTBTj4jIRe8FnpvurLTSS3IvOsTccFkbY7eyxlMQJc'
);

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

// ========== FONCTIONS ==========
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  if (!req.session.user?.is_admin) return res.status(403).send('🔒 Accès admin refusé');
  next();
}

// ========== AUTH ==========
app.get('/login', (req, res) => { res.render('login'); });
app.get('/register', (req, res) => { res.render('register'); });

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single();
  
  if (error || !user || !(await bcrypt.compare(password, user.password))) {
    return res.send('❌ Identifiants invalides. <a href="/login">Réessayer</a>');
  }
  
  req.session.userId = user.id;
  req.session.user = user;
  res.redirect('/');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const { error } = await supabase
    .from('users')
    .insert({ username, password: hashedPassword, rank: 'user' });
  
  if (error) return res.send('❌ Nom déjà pris. <a href="/register">Réessayer</a>');
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ========== FIL D'ACTUALITÉ ==========
app.get('/', requireAuth, async (req, res) => {
  const { data: posts, error } = await supabase
    .from('posts')
    .select(`
      *,
      users (username, rank)
    `)
    .order('created_at', { ascending: false });
  
  res.render('index', { user: req.session.user, posts: posts || [] });
});

app.post('/api/post', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.length > 500) return res.status(400).json({ error: 'Message trop long' });
  
  const { error } = await supabase
    .from('posts')
    .insert({ user_id: req.session.userId, content });
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ========== MESSAGERIE ==========
app.get('/messages', requireAuth, async (req, res) => {
  // Récupérer tous les utilisateurs sauf moi + dernier message
  const { data: users, error } = await supabase
    .from('users')
    .select('id, username, rank')
    .neq('id', req.session.userId);
  
  // Pour chaque utilisateur, récupérer le dernier message
  const conversations = [];
  for (const otherUser of (users || [])) {
    const { data: lastMsg } = await supabase
      .from('messages')
      .select('content, created_at')
      .or(`and(sender_id.eq.${req.session.userId},receiver_id.eq.${otherUser.id}),and(sender_id.eq.${otherUser.id},receiver_id.eq.${req.session.userId})`)
      .order('created_at', { ascending: false })
      .limit(1);
    
    const { count: unread } = await supabase
      .from('messages')
      .select('*', { count: 'exact', head: true })
      .eq('sender_id', otherUser.id)
      .eq('receiver_id', req.session.userId)
      .eq('is_read', 0);
    
    conversations.push({
      id: otherUser.id,
      username: otherUser.username,
      rank: otherUser.rank,
      last_message: lastMsg?.[0]?.content || null,
      last_date: lastMsg?.[0]?.created_at || null,
      unread: unread || 0
    });
  }
  
  // Trier par date du dernier message
  conversations.sort((a, b) => (b.last_date || 0) - (a.last_date || 0));
  
  res.render('messages', { user: req.session.user, conversations });
});

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  const otherId = parseInt(req.params.userId);
  
  const { data: messages, error } = await supabase
    .from('messages')
    .select(`
      *,
      sender:users!messages_sender_id_fkey(username)
    `)
    .or(`and(sender_id.eq.${req.session.userId},receiver_id.eq.${otherId}),and(sender_id.eq.${otherId},receiver_id.eq.${req.session.userId})`)
    .order('created_at', { ascending: true });
  
  if (error) return res.status(500).json({ error: error.message });
  
  // Marquer les messages reçus comme lus
  await supabase
    .from('messages')
    .update({ is_read: 1 })
    .eq('sender_id', otherId)
    .eq('receiver_id', req.session.userId)
    .eq('is_read', 0);
  
  const formattedMessages = messages.map(m => ({
    id: m.id,
    sender_id: m.sender_id,
    receiver_id: m.receiver_id,
    content: m.content,
    created_at: m.created_at,
    is_read: m.is_read,
    username: m.sender?.username
  }));
  
  res.json(formattedMessages);
});

app.post('/api/messages/send', requireAuth, async (req, res) => {
  const { receiver_id, content } = req.body;
  if (!content || content.length > 1000) return res.status(400).json({ error: 'Message trop long' });
  
  const { error } = await supabase
    .from('messages')
    .insert({ sender_id: req.session.userId, receiver_id, content });
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ========== PROFIL ==========
app.get('/profile/:id', requireAuth, async (req, res) => {
  const targetId = parseInt(req.params.id);
  
  const { data: targetUser, error } = await supabase
    .from('users')
    .select('id, username, bio, avatar, rank, created_at')
    .eq('id', targetId)
    .single();
  
  if (error || !targetUser) return res.status(404).send('Utilisateur non trouvé');
  
  const { data: posts } = await supabase
    .from('posts')
    .select('*')
    .eq('user_id', targetId)
    .order('created_at', { ascending: false });
  
  res.render('profile', { user: req.session.user, targetUser, posts: posts || [] });
});

app.post('/api/profile/bio', requireAuth, async (req, res) => {
  const { bio } = req.body;
  if (bio.length > 300) return res.status(400).json({ error: 'Bio trop longue' });
  
  const { error } = await supabase
    .from('users')
    .update({ bio })
    .eq('id', req.session.userId);
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ========== ADMIN : GESTION DES UTILISATEURS ==========
app.get('/admin/users', requireAdmin, async (req, res) => {
  res.render('admin-users');
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, username, is_admin, rank, bio, created_at');
  
  if (error) return res.status(500).json({ error: error.message });
  
  const formattedUsers = users.map(u => ({
    ...u,
    rank: u.is_admin ? 'admin' : (u.rank || 'user')
  }));
  res.json(formattedUsers);
});

app.post('/api/admin/users/rank', requireAdmin, async (req, res) => {
  const { userId, rank } = req.body;
  const validRanks = ['user', 'vip', 'premium', 'tester', 'banned', 'admin'];
  if (!validRanks.includes(rank)) return res.status(400).json({ error: 'Rang invalide' });
  
  const isAdmin = (rank === 'admin') ? 1 : 0;
  const { error } = await supabase
    .from('users')
    .update({ is_admin: isAdmin, rank })
    .eq('id', userId);
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/admin/users/delete', requireAdmin, async (req, res) => {
  const { userId } = req.body;
  if (userId == req.session.userId) return res.status(400).json({ error: "Impossible de se supprimer" });
  
  const { error } = await supabase
    .from('users')
    .delete()
    .eq('id', userId);
  
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Redirection ancien admin
app.get('/admin', requireAdmin, (req, res) => {
  res.redirect('/admin/users');
});
// ========== ROUTE TEMPORAIRE POUR CRÉER L'ADMIN ==========
app.get('/setup', async (req, res) => {
  const bcrypt = require('bcrypt');
  const hashedPassword = await bcrypt.hash('azertydox1234', 10);
  
  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('username', 'Kalinux')
    .single();
  
  if (existingUser) {
    // Mettre à jour l'utilisateur existant
    await supabase
      .from('users')
      .update({ is_admin: 1, rank: 'admin', password: hashedPassword })
      .eq('username', 'Kalinux');
    return res.send('✅ Admin mis à jour ! Va te connecter avec Kalinux / azertydox1234');
  }
  
  // Créer un nouvel admin
  const { error } = await supabase
    .from('users')
    .insert({
      username: 'Kalinux',
      password: hashedPassword,
      is_admin: 1,
      rank: 'admin'
    });
  
  if (error) return res.send('❌ Erreur: ' + error.message);
  res.send('✅ Admin créé avec succès ! Va te connecter avec Kalinux / azertydox1234');
});
// ========== DÉMARRAGE ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ KaliNet sur http://0.0.0.0:${PORT}`);
  console.log(`👑 Admin: Kalinux / azertydox1234`);
});
