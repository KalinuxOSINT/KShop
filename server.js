require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
const PORT = process.env.PORT || 8080;

// ========== SUPABASE CLIENT ==========
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

// ========== FONCTIONS D'AUTH (avec rafraîchissement du rang) ==========
async function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    
    // Recharger l'utilisateur depuis la base pour être sûr du rang
    const { data: user, error } = await supabase
        .from('users')
        .select('id, username, is_admin, rank, bio, avatar')
        .eq('id', req.session.userId)
        .single();
    
    if (error || !user) {
        req.session.destroy();
        return res.redirect('/login');
    }
    
    // Mettre à jour la session avec les infos récentes
    req.session.user = user;
    
    // Bloquer les bannis
    if (user.rank === 'banned') {
        req.session.destroy();
        return res.status(403).send('⛔ Vous êtes banni. Contactez l\'administrateur.');
    }
    
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    if (!req.session.user?.is_admin) return res.status(403).send('🔒 Accès admin refusé');
    next();
}

// ========== ROUTES PUBLIQUES ==========
app.get('/login', (req, res) => { res.render('login'); });
app.get('/register', (req, res) => { res.render('register'); });

// ========== DÉCONNEXION (redirige vers /login) ==========
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error(err);
        res.redirect('/login');
    });
});

// ========== AUTH POST ==========
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
    
    if (user.rank === 'banned') {
        return res.send('⛔ Ce compte est banni. Contactez l\'administrateur.');
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

// ========== FIL D'ACTUALITÉ ==========
app.get('/', requireAuth, async (req, res) => {
    const { data: posts, error } = await supabase
        .from('posts')
        .select(`
            id,
            content,
            created_at,
            user_id,
            users (username, rank)
        `)
        .neq('users.rank', 'banned')
        .order('created_at', { ascending: false });
    
    if (error) {
        console.error("Erreur Supabase:", error);
        return res.render('index', { user: req.session.user, posts: [] });
    }
    
    const formattedPosts = posts.map(post => ({
        id: post.id,
        content: post.content,
        created_at: post.created_at,
        user_id: post.user_id,
        users: {
            username: post.users?.username || 'Inconnu',
            rank: post.users?.rank || 'user'
        }
    }));
    
    res.render('index', { user: req.session.user, posts: formattedPosts });
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

app.post('/api/post/delete', requireAuth, async (req, res) => {
    const { postId } = req.body;
    
    const { data: post, error } = await supabase
        .from('posts')
        .select('user_id')
        .eq('id', postId)
        .single();
    
    if (error || !post) return res.status(404).json({ error: 'Post non trouvé' });
    
    const isAuthor = (post.user_id === req.session.userId);
    const isAdmin = req.session.user?.is_admin === 1;
    
    if (!isAuthor && !isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    
    const { error: deleteError } = await supabase
        .from('posts')
        .delete()
        .eq('id', postId);
    
    if (deleteError) return res.status(500).json({ error: deleteError.message });
    res.json({ success: true });
});

// ========== SIGNALEMENTS ==========
app.post('/api/post/report', requireAuth, async (req, res) => {
    const { postId, reason } = req.body;
    if (!postId || !reason) return res.status(400).json({ error: 'Post ID et raison requis' });
    if (reason.length > 500) return res.status(400).json({ error: 'Raison trop longue' });
    
    const { data: existing } = await supabase
        .from('reports')
        .select('id')
        .eq('post_id', postId)
        .eq('reporter_id', req.session.userId)
        .single();
    
    if (existing) return res.status(400).json({ error: 'Vous avez déjà signalé ce post' });
    
    const { error } = await supabase
        .from('reports')
        .insert({ post_id: postId, reporter_id: req.session.userId, reason });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.get('/admin/reports', requireAdmin, async (req, res) => {
    const { data: reports, error } = await supabase
        .from('reports')
        .select(`
            *,
            posts(id, content, users(id, username)),
            reporter:users!reports_reporter_id_fkey(id, username)
        `)
        .order('created_at', { ascending: false });
    
    res.render('admin-reports', { user: req.session.user, reports: reports || [] });
});

app.post('/api/admin/reports/delete-post', requireAdmin, async (req, res) => {
    const { postId, reportId } = req.body;
    
    const { error: postError } = await supabase
        .from('posts')
        .delete()
        .eq('id', postId);
    
    if (postError) return res.status(500).json({ error: postError.message });
    
    await supabase
        .from('reports')
        .update({ status: 'resolved' })
        .eq('id', reportId);
    
    res.json({ success: true });
});

app.post('/api/admin/reports/ignore', requireAdmin, async (req, res) => {
    const { reportId } = req.body;
    
    await supabase
        .from('reports')
        .update({ status: 'ignored' })
        .eq('id', reportId);
    
    res.json({ success: true });
});

// ========== MESSAGERIE ==========
app.get('/messages', requireAuth, async (req, res) => {
    const { data: users, error } = await supabase
        .from('users')
        .select('id, username, rank')
        .neq('id', req.session.userId)
        .neq('rank', 'banned');
    
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
    
    conversations.sort((a, b) => (b.last_date || 0) - (a.last_date || 0));
    res.render('messages', { user: req.session.user, conversations });
});

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
    const otherId = parseInt(req.params.userId);
    
    const { data: messages, error } = await supabase
        .from('messages')
        .select(`
            *,
            sender:users!messages_sender_id_fkey(username, rank)
        `)
        .or(`and(sender_id.eq.${req.session.userId},receiver_id.eq.${otherId}),and(sender_id.eq.${otherId},receiver_id.eq.${req.session.userId})`)
        .order('created_at', { ascending: true });
    
    if (error) return res.status(500).json({ error: error.message });
    
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
        username: m.sender?.username,
        sender_rank: m.sender?.rank
    }));
    
    res.json(formattedMessages);
});

app.post('/api/messages/send', requireAuth, async (req, res) => {
    const { receiver_id, content } = req.body;
    if (!content || content.length > 1000) return res.status(400).json({ error: 'Message trop long' });
    
    const { data: receiver } = await supabase
        .from('users')
        .select('rank')
        .eq('id', receiver_id)
        .single();
    if (receiver?.rank === 'banned') {
        return res.status(403).json({ error: "Impossible d'envoyer un message à un utilisateur banni." });
    }
    
    const { error } = await supabase
        .from('messages')
        .insert({ sender_id: req.session.userId, receiver_id, content });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.post('/api/messages/upload', requireAuth, upload.single('file'), async (req, res) => {
    const { receiver_id } = req.body;
    const file = req.file;
    
    if (!file) return res.status(400).json({ error: 'Aucun fichier' });
    if (file.size > 10 * 1024 * 1024) return res.status(400).json({ error: 'Fichier trop gros (max 10MB)' });
    
    const fileExt = file.originalname.split('.').pop();
    const fileName = `${Date.now()}_${Math.random().toString(36).substring(7)}.${fileExt}`;
    
    const { data, error } = await supabase.storage
        .from('kalinet-files')
        .upload(fileName, file.buffer, { contentType: file.mimetype });
    
    if (error) return res.status(500).json({ error: error.message });
    
    const fileUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/kalinet-files/${fileName}`;
    
    const { error: msgError } = await supabase
        .from('messages')
        .insert({
            sender_id: req.session.userId,
            receiver_id: parseInt(receiver_id),
            content: `📎 ${file.originalname} : ${fileUrl}`
        });
    
    if (msgError) return res.status(500).json({ error: msgError.message });
    res.json({ success: true, fileUrl });
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
    
    let posts = [];
    if (targetUser.rank !== 'banned') {
        const { data } = await supabase
            .from('posts')
            .select('*')
            .eq('user_id', targetId)
            .order('created_at', { ascending: false });
        posts = data || [];
    }
    
    res.render('profile', { user: req.session.user, targetUser, posts });
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

// ========== ADMIN ==========
app.get('/admin/users', requireAdmin, async (req, res) => {
    res.render('admin-users');
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    const { data: users, error } = await supabase
        .from('users')
        .select('id, username, is_admin, rank, bio, created_at')
        .order('id', { ascending: true });
    
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
    
    if (rank === 'banned') {
        const { data: bannedUsers } = await supabase
            .from('users')
            .select('id')
            .eq('rank', 'banned');
        
        const newBannedNumber = (bannedUsers?.length || 0) + 1;
        const newUsername = `banned_user-${newBannedNumber}`;
        
        await supabase
            .from('users')
            .update({ username: newUsername })
            .eq('id', userId);
    }
    
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

app.get('/admin', requireAdmin, (req, res) => {
    res.redirect('/admin/users');
});

// ========== TICKETS ==========
app.get('/contact', requireAuth, (req, res) => {
    res.render('contact', { user: req.session.user });
});

app.post('/api/contact', requireAuth, async (req, res) => {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Sujet et message requis' });
    
    const { error } = await supabase
        .from('contact_messages')
        .insert({ user_id: req.session.userId, subject, message });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.get('/my-tickets', requireAuth, async (req, res) => {
    const { data: tickets, error } = await supabase
        .from('contact_messages')
        .select('*')
        .eq('user_id', req.session.userId)
        .order('created_at', { ascending: false });
    
    res.render('my-tickets', { user: req.session.user, tickets: tickets || [] });
});

app.get('/admin/messages', requireAdmin, async (req, res) => {
    const { data: messages, error } = await supabase
        .from('contact_messages')
        .select(`*, users(id, username)`)
        .order('created_at', { ascending: false });
    
    res.render('admin-messages', { user: req.session.user, messages: messages || [] });
});

app.post('/api/admin/messages/reply', requireAdmin, async (req, res) => {
    const { messageId, reply } = req.body;
    if (!reply) return res.status(400).json({ error: 'Réponse requise' });
    
    const { error } = await supabase
        .from('contact_messages')
        .update({ admin_reply: reply, status: 'replied', replied_at: new Date() })
        .eq('id', messageId);
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.post('/api/admin/messages/resolve', requireAdmin, async (req, res) => {
    const { messageId } = req.body;
    const { error } = await supabase
        .from('contact_messages')
        .update({ status: 'resolved' })
        .eq('id', messageId);
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.get('/api/admin/messages/unread-count', requireAdmin, async (req, res) => {
    const { count, error } = await supabase
        .from('contact_messages')
        .select('*', { count: 'exact', head: true })
        .eq('status', 'pending');
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ count: count || 0 });
});

// ========== DÉMARRAGE ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ KaliNet sur http://0.0.0.0:${PORT}`);
    console.log(`👑 Admin: Kalinux / azertydox1234`);
});
