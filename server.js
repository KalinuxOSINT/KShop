require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

// Vérification des variables d'environnement obligatoires
if (!process.env.SUPABASE_URL) throw new Error('SUPABASE_URL manquant');
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('SUPABASE_SERVICE_ROLE_KEY manquant');
if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET manquant');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL manquant');

const app = express();
const PORT = process.env.PORT || 8080;

app.set('trust proxy', 1);

// ========== TIMEOUT ANTI-SLOWLORIS ==========
// Coupe les connexions qui restent ouvertes trop longtemps sans envoyer de données
app.use((req, res, next) => {
    req.setTimeout(10000, () => {
        res.status(408).send('Request Timeout');
    });
    res.setTimeout(10000, () => {
        res.status(408).send('Response Timeout');
    });
    next();
});

// ========== LIMITE TAILLE DES REQUÊTES ==========
// Rejette immédiatement les requêtes avec un body trop grand (anti ContentLength fake)
app.use((req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > 50 * 1024) { // max 50KB
        return res.status(413).send('Payload trop grand.');
    }
    next();
});

// ========== PROTECTION DDOS / RATE LIMITING ==========
const rateLimit   = new Map();
const postLimit   = new Map(); // rate limit spécifique aux POST
const bannedIPs   = new Map();

const RATE_WINDOW      = 60 * 1000;  // fenêtre 1 minute
const RATE_MAX         = 100;        // max 100 requêtes/min toutes routes
const POST_MAX         = 10;         // max 10 POST/min (login/register)
const RATE_BAN         = 15 * 60 * 1000; // ban 15 min

function getIP(req) {
    return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
}

function checkLimit(map, key, max, window) {
    const now = Date.now();
    if (!map.has(key)) {
        map.set(key, { count: 1, start: now });
        return false;
    }
    const entry = map.get(key);
    if (now - entry.start > window) {
        entry.count = 1;
        entry.start = now;
        return false;
    }
    entry.count++;
    return entry.count > max;
}

// Nettoyage toutes les 5 minutes pour éviter les fuites mémoire
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateLimit) { if (now - v.start > RATE_WINDOW * 2) rateLimit.delete(k); }
    for (const [k, v] of postLimit) { if (now - v.start > RATE_WINDOW * 2) postLimit.delete(k); }
    for (const [k, v] of bannedIPs) { if (now > v) bannedIPs.delete(k); }
}, 5 * 60 * 1000);

app.use((req, res, next) => {
    const ip = getIP(req);
    const now = Date.now();

    // IP bannie ?
    if (bannedIPs.has(ip) && now < bannedIPs.get(ip)) {
        const remaining = Math.ceil((bannedIPs.get(ip) - now) / 60000);
        return res.status(429).send(`Accès bloqué. Réessaie dans ${remaining} min.`);
    }

    // Rate limit global
    if (checkLimit(rateLimit, ip, RATE_MAX, RATE_WINDOW)) {
        bannedIPs.set(ip, now + RATE_BAN);
        rateLimit.delete(ip);
        console.warn(`[DDoS] IP bannie (rate global) : ${ip}`);
        return res.status(429).send('Trop de requêtes. Accès bloqué 15 minutes.');
    }

    // Rate limit POST strict (login, register, api)
    if (req.method === 'POST') {
        if (checkLimit(postLimit, ip, POST_MAX, RATE_WINDOW)) {
            bannedIPs.set(ip, now + RATE_BAN);
            postLimit.delete(ip);
            console.warn(`[DDoS] IP bannie (POST flood) : ${ip}`);
            return res.status(429).send('Trop de requêtes POST. Accès bloqué 15 minutes.');
        }
    }

    next();
});

// ========== LISTE NOIRE DE PSEUDOS ==========
const BANNED_USERNAMES = ['wazroshh', 'mq2b'];

// Supprimer les comptes bannis au démarrage
async function deleteBannedUsers() {
    for (const username of BANNED_USERNAMES) {
        const { data } = await supabase
            .from('users')
            .select('id, username')
            .ilike('username', `%${username}%`);
        if (data && data.length > 0) {
            for (const user of data) {
                await supabase.from('users').delete().eq('id', user.id);
                console.log(`[BANNED] Compte supprimé : ${user.username}`);
            }
        }
    }
}
deleteBannedUsers();

// ========== SUPABASE CLIENT ==========
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Désactive la vérification SSL pour Supabase pooler (certificat auto-signé)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ========== SESSION STORE (Supabase custom) ==========
const Store = require('express-session').Store;

class SupabaseStore extends Store {
    constructor(supabaseClient) {
        super();
        this.supabase = supabaseClient;
    }
    async get(sid, callback) {
        try {
            const { data } = await this.supabase.from('session').select('sess, expire').eq('sid', sid).single();
            if (!data) return callback(null, null);
            if (new Date(data.expire) < new Date()) {
                await this.destroy(sid, () => {});
                return callback(null, null);
            }
            callback(null, data.sess);
        } catch (e) { callback(null, null); }
    }
    async set(sid, session, callback) {
        try {
            const expire = new Date(Date.now() + (session.cookie?.maxAge || 86400000));
            const { error } = await this.supabase.from('session').upsert({ sid, sess: session, expire });
            if (error) {
                console.error('SupabaseStore.set error:', error);
                return callback(error);
            }
            callback(null);
        } catch (e) { 
            console.error('SupabaseStore.set exception:', e);
            callback(e); 
        }
    }
    async destroy(sid, callback) {
        try {
            await this.supabase.from('session').delete().eq('sid', sid);
            callback(null);
        } catch (e) { callback(e); }
    }
}

// ========== MIDDLEWARE ==========
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    store: new SupabaseStore(supabase),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ========== FONCTIONS D'AUTH ==========
async function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    
    const { data: user, error } = await supabase
        .from('users')
        .select('id, username, is_admin, rank, bio, avatar')
        .eq('id', req.session.userId)
        .single();
    
    if (error || !user) {
        req.session.destroy();
        return res.redirect('/login');
    }
    
    req.session.user = user;
    if (user.rank === 'banned') {
        req.session.destroy();
        return res.status(403).send('⛔ Vous êtes banni.');
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

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('LOGIN attempt:', username);
    
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();
    
    console.log('DB result:', user ? 'found' : 'not found', error ? error.message : '');
    
    if (error || !user || !(await bcrypt.compare(password, user.password))) {
        console.log('AUTH FAILED');
        return res.send('❌ Identifiants invalides. <a href="/login">Réessayer</a>');
    }
    if (user.rank === 'banned') {
        return res.send('⛔ Ce compte est banni.');
    }
    
    req.session.userId = user.id;
    req.session.user = user;
    console.log('SESSION set, saving...');
    req.session.save((err) => {
        if (err) {
            console.error('SESSION SAVE ERROR:', err);
            return res.send('❌ Erreur de session. <a href="/login">Réessayer</a>');
        }
        console.log('SESSION saved OK, redirecting to /');
        res.redirect('/');
    });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Vérifier pseudo interdit
    const isBanned = BANNED_USERNAMES.some(b => username.toLowerCase().includes(b.toLowerCase()));
    if (isBanned) return res.send('❌ Ce pseudo n\'est pas autorisé.');

    const hashedPassword = await bcrypt.hash(password, 10);
    const { error } = await supabase
        .from('users')
        .insert({ username, password: hashedPassword, rank: 'user' });
    if (error) return res.send('❌ Nom déjà pris.');
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
        console.error(error);
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
    const { error } = await supabase.from('posts').insert({ user_id: req.session.userId, content });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

// === ROUTE DE SUPPRESSION CORRIGÉE (admin peut tout supprimer) ===
app.post('/api/post/delete', requireAuth, async (req, res) => {
    const { postId } = req.body;
    
    const { data: post, error } = await supabase
        .from('posts')
        .select('user_id')
        .eq('id', postId)
        .single();
    
    if (error || !post) return res.status(404).json({ error: 'Post non trouvé' });
    
    const isAuthor = (post.user_id === req.session.userId);
    const isAdmin = req.session.user && req.session.user.is_admin === 1; // ← vérification stricte
    
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
    if (existing) return res.status(400).json({ error: 'Déjà signalé' });
    
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
    const { error: postError } = await supabase.from('posts').delete().eq('id', postId);
    if (postError) return res.status(500).json({ error: postError.message });
    await supabase.from('reports').update({ status: 'resolved' }).eq('id', reportId);
    res.json({ success: true });
});

app.post('/api/admin/reports/ignore', requireAdmin, async (req, res) => {
    const { reportId } = req.body;
    await supabase.from('reports').update({ status: 'ignored' }).eq('id', reportId);
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
    await supabase.from('messages').update({ is_read: 1 })
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
    const { data: receiver } = await supabase.from('users').select('rank').eq('id', receiver_id).single();
    if (receiver?.rank === 'banned') {
        return res.status(403).json({ error: "Destinataire banni." });
    }
    const { error } = await supabase.from('messages').insert({ sender_id: req.session.userId, receiver_id, content });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.post('/api/messages/upload', requireAuth, upload.single('file'), async (req, res) => {
    const { receiver_id } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Aucun fichier' });
    if (file.size > 10 * 1024 * 1024) return res.status(400).json({ error: 'Fichier trop gros' });
    const fileExt = file.originalname.split('.').pop();
    const fileName = `${Date.now()}_${Math.random().toString(36).substring(7)}.${fileExt}`;
    const { data, error } = await supabase.storage.from('kalinet-files').upload(fileName, file.buffer, { contentType: file.mimetype });
    if (error) return res.status(500).json({ error: error.message });
    const fileUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/kalinet-files/${fileName}`;
    const { error: msgError } = await supabase.from('messages').insert({
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
    const { error } = await supabase.from('users').update({ bio }).eq('id', req.session.userId);
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
        const { data: bannedUsers } = await supabase.from('users').select('id').eq('rank', 'banned');
        const newBannedNumber = (bannedUsers?.length || 0) + 1;
        const newUsername = `banned_user-${newBannedNumber}`;
        await supabase.from('users').update({ username: newUsername }).eq('id', userId);
    }
    const isAdmin = (rank === 'admin') ? 1 : 0;
    const { error } = await supabase.from('users').update({ is_admin: isAdmin, rank }).eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.post('/api/admin/users/delete', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    if (userId == req.session.userId) return res.status(400).json({ error: "Impossible de se supprimer" });
    const { error } = await supabase.from('users').delete().eq('id', userId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.get('/admin', requireAdmin, (req, res) => {
    res.redirect('/admin/users');
});

// ========== TICKETS ==========
app.get('/contact', requireAuth, (req, res) => { res.render('contact', { user: req.session.user }); });
app.post('/api/contact', requireAuth, async (req, res) => {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Sujet et message requis' });
    const { error } = await supabase.from('contact_messages').insert({ user_id: req.session.userId, subject, message });
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
    const { error } = await supabase.from('contact_messages').update({ status: 'resolved' }).eq('id', messageId);
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

// ========== ROUTES PIN (conversation) ==========
function getConvId(a, b) { return a < b ? `${a}-${b}` : `${b}-${a}`; }

app.get('/api/conversation/has-pin/:userId', requireAuth, async (req, res) => {
    const otherId = parseInt(req.params.userId);
    const u1 = Math.min(req.session.userId, otherId);
    const u2 = Math.max(req.session.userId, otherId);
    const { data, error } = await supabase
        .from('conversation_pins')
        .select('pin_hash')
        .eq('user1_id', u1)
        .eq('user2_id', u2)
        .single();
    if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });
    res.json({ hasPin: !!data });
});

app.post('/api/conversation/set-pin', requireAuth, async (req, res) => {
    const { otherId, pin } = req.body;
    if (!pin || pin.length < 4 || !/^\d+$/.test(pin)) return res.status(400).json({ error: 'PIN invalide' });
    const u1 = Math.min(req.session.userId, otherId);
    const u2 = Math.max(req.session.userId, otherId);
    const pinHash = await bcrypt.hash(pin, 10);
    const { data: existing } = await supabase
        .from('conversation_pins')
        .select('id')
        .eq('user1_id', u1)
        .eq('user2_id', u2)
        .single();
    if (existing) return res.status(403).json({ error: 'PIN déjà défini. Utilisez la réinitialisation.' });
    const { error } = await supabase
        .from('conversation_pins')
        .insert({ user1_id: u1, user2_id: u2, pin_hash: pinHash });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
});

app.post('/api/conversation/verify-pin', requireAuth, async (req, res) => {
    const { otherId, pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN requis' });
    const u1 = Math.min(req.session.userId, otherId);
    const u2 = Math.max(req.session.userId, otherId);
    const { data, error } = await supabase
        .from('conversation_pins')
        .select('pin_hash')
        .eq('user1_id', u1)
        .eq('user2_id', u2)
        .single();
    if (error || !data) return res.status(404).json({ error: 'Aucun PIN défini' });
    const valid = await bcrypt.compare(pin, data.pin_hash);
    if (!valid) return res.status(401).json({ error: 'PIN incorrect' });
    const key = getConvId(req.session.userId, otherId);
    if (!req.session.unlockedConversations) req.session.unlockedConversations = [];
    if (!req.session.unlockedConversations.includes(key)) {
        req.session.unlockedConversations.push(key);
    }
    res.json({ success: true });
});

app.post('/api/conversation/request-reset', requireAuth, async (req, res) => {
    const { otherId } = req.body;
    const u1 = Math.min(req.session.userId, otherId);
    const u2 = Math.max(req.session.userId, otherId);
    const { data, error } = await supabase
        .from('conversation_pins')
        .select('id')
        .eq('user1_id', u1)
        .eq('user2_id', u2)
        .single();
    if (error || !data) return res.status(404).json({ error: 'Aucun PIN défini' });
    await supabase
        .from('conversation_pins')
        .update({ reset_requested_by: req.session.userId, reset_requested_at: new Date(), reset_approved_by: null })
        .eq('id', data.id);
    res.json({ success: true });
});

app.post('/api/conversation/approve-reset', requireAuth, async (req, res) => {
    const { otherId } = req.body;
    const u1 = Math.min(req.session.userId, otherId);
    const u2 = Math.max(req.session.userId, otherId);
    const { data, error } = await supabase
        .from('conversation_pins')
        .select('id, reset_requested_by')
        .eq('user1_id', u1)
        .eq('user2_id', u2)
        .single();
    if (error || !data) return res.status(404).json({ error: 'Aucun PIN défini' });
    if (!data.reset_requested_by) return res.status(400).json({ error: 'Aucune demande en cours' });
    if (data.reset_requested_by === req.session.userId) return res.status(400).json({ error: 'Vous ne pouvez pas approuver votre propre demande' });
    await supabase.from('conversation_pins').delete().eq('id', data.id);
    const key = getConvId(req.session.userId, otherId);
    if (req.session.unlockedConversations) {
        req.session.unlockedConversations = req.session.unlockedConversations.filter(k => k !== key);
    }
    res.json({ success: true });
});

// ========== SERVEURS ==========

// Liste de tous les serveurs
app.get('/servers', requireAuth, async (req, res) => {
    const { data: allServers } = await supabase
        .from('servers')
        .select('*, users!servers_owner_id_fkey(username)')
        .order('created_at', { ascending: false });

    const { data: myMemberships } = await supabase
        .from('server_members')
        .select('server_id')
        .eq('user_id', req.session.userId);

    const myServerIds = (myMemberships || []).map(m => m.server_id);

    const servers = (allServers || []).map(s => ({
        ...s,
        owner_username: s.users?.username,
        is_member: myServerIds.includes(s.id),
        is_owner: s.owner_id === req.session.userId
    }));

    res.render('servers', { user: req.session.user, servers });
});

// Créer un serveur
app.post('/api/servers/create', requireAuth, async (req, res) => {
    const { name, description, icon } = req.body;
    if (!name || name.length > 100) return res.status(400).json({ error: 'Nom invalide' });

    const { data: server, error } = await supabase
        .from('servers')
        .insert({ name, description: description || '', icon: icon || '🌐', owner_id: req.session.userId })
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });

    // Owner devient automatiquement membre
    await supabase.from('server_members').insert({ server_id: server.id, user_id: req.session.userId });

    // Créer salon #général par défaut
    await supabase.from('server_channels').insert({ server_id: server.id, name: 'général', position: 0 });

    // Créer rôle @everyone par défaut
    await supabase.from('server_roles').insert({ server_id: server.id, name: 'Membre', color: '#94a3b8', position: 0 });

    res.json({ success: true, serverId: server.id });
});

// Rejoindre un serveur
app.post('/api/servers/:id/join', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const { error } = await supabase
        .from('server_members')
        .insert({ server_id: serverId, user_id: req.session.userId });
    if (error) return res.status(400).json({ error: 'Déjà membre ou serveur introuvable' });
    res.json({ success: true });
});

// Quitter un serveur
app.post('/api/servers/:id/leave', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (server?.owner_id === req.session.userId) return res.status(400).json({ error: 'Le propriétaire ne peut pas quitter son serveur' });
    await supabase.from('server_members').delete().eq('server_id', serverId).eq('user_id', req.session.userId);
    res.json({ success: true });
});

// Supprimer un serveur (owner only)
app.post('/api/servers/:id/delete', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || (server.owner_id !== req.session.userId && !req.session.user?.is_admin)) {
        return res.status(403).json({ error: 'Non autorisé' });
    }
    await supabase.from('servers').delete().eq('id', serverId);
    res.json({ success: true });
});

// Page intérieure d'un serveur
app.get('/servers/:id', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);

    const { data: server } = await supabase
        .from('servers')
        .select('*, users!servers_owner_id_fkey(username)')
        .eq('id', serverId)
        .single();

    if (!server) return res.status(404).send('Serveur introuvable');

    // Vérifier si membre
    const { data: membership } = await supabase
        .from('server_members')
        .select('id')
        .eq('server_id', serverId)
        .eq('user_id', req.session.userId)
        .single();

    if (!membership) return res.redirect('/servers');

    // Salons
    const { data: channels } = await supabase
        .from('server_channels')
        .select('*')
        .eq('server_id', serverId)
        .order('position');

    // Membres avec leurs rôles
    const { data: members } = await supabase
        .from('server_members')
        .select('user_id, users(id, username, rank)')
        .eq('server_id', serverId);

    // Rôles du serveur
    const { data: roles } = await supabase
        .from('server_roles')
        .select('*')
        .eq('server_id', serverId)
        .order('position', { ascending: false });

    // Rôles assignés
    const { data: memberRoles } = await supabase
        .from('server_member_roles')
        .select('user_id, role_id, server_roles(name, color)')
        .eq('server_id', serverId);

    // Grouper les rôles par user
    const rolesByUser = {};
    for (const mr of (memberRoles || [])) {
        if (!rolesByUser[mr.user_id]) rolesByUser[mr.user_id] = [];
        rolesByUser[mr.user_id].push({ id: mr.role_id, name: mr.server_roles?.name, color: mr.server_roles?.color });
    }

    const formattedMembers = (members || []).map(m => ({
        id: m.user_id,
        username: m.users?.username,
        rank: m.users?.rank,
        roles: rolesByUser[m.user_id] || []
    }));

    // Canal actif (premier par défaut)
    const activeChannelId = parseInt(req.query.channel) || channels?.[0]?.id;
    let messages = [];
    if (activeChannelId) {
        const { data: msgs } = await supabase
            .from('channel_messages')
            .select('*, users(username, rank)')
            .eq('channel_id', activeChannelId)
            .order('created_at', { ascending: true })
            .limit(100);
        messages = (msgs || []).map(m => ({
            ...m,
            username: m.users?.username,
            user_rank: m.users?.rank,
            user_roles: rolesByUser[m.user_id] || []
        }));
    }

    res.render('server', {
        user: req.session.user,
        server: { ...server, owner_username: server.users?.username },
        channels: channels || [],
        members: formattedMembers,
        roles: roles || [],
        activeChannelId,
        messages,
        isOwner: server.owner_id === req.session.userId
    });
});

// Envoyer un message dans un salon
app.post('/api/channels/:id/messages', requireAuth, async (req, res) => {
    const channelId = parseInt(req.params.id);
    const { content } = req.body;
    if (!content || content.length > 2000) return res.status(400).json({ error: 'Message invalide' });

    // Vérifier que l'user est membre du serveur de ce salon
    const { data: channel } = await supabase.from('server_channels').select('server_id').eq('id', channelId).single();
    if (!channel) return res.status(404).json({ error: 'Salon introuvable' });

    const { data: membership } = await supabase.from('server_members')
        .select('id').eq('server_id', channel.server_id).eq('user_id', req.session.userId).single();
    if (!membership) return res.status(403).json({ error: 'Non membre' });

    const { data: msg, error } = await supabase
        .from('channel_messages')
        .insert({ channel_id: channelId, user_id: req.session.userId, content })
        .select('*, users(username, rank)')
        .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, message: { ...msg, username: msg.users?.username, user_rank: msg.users?.rank } });
});

// Récupérer les messages d'un salon (polling)
app.get('/api/channels/:id/messages', requireAuth, async (req, res) => {
    const channelId = parseInt(req.params.id);
    const after = req.query.after;

    const { data: channel } = await supabase.from('server_channels').select('server_id').eq('id', channelId).single();
    if (!channel) return res.status(404).json({ error: 'Salon introuvable' });

    const { data: membership } = await supabase.from('server_members')
        .select('id').eq('server_id', channel.server_id).eq('user_id', req.session.userId).single();
    if (!membership) return res.status(403).json({ error: 'Non membre' });

    let query = supabase.from('channel_messages').select('*, users(username, rank)')
        .eq('channel_id', channelId).order('created_at', { ascending: true }).limit(100);
    if (after) query = query.gt('id', after);

    const { data: msgs } = await query;
    res.json((msgs || []).map(m => ({ ...m, username: m.users?.username, user_rank: m.users?.rank })));
});

// Créer un salon (owner only)
app.post('/api/servers/:id/channels', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Nom requis' });

    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });

    const { data: channel, error } = await supabase.from('server_channels')
        .insert({ server_id: serverId, name: name.toLowerCase().replace(/\s+/g, '-') })
        .select().single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, channel });
});

// Supprimer un salon (owner only)
app.post('/api/channels/:id/delete', requireAuth, async (req, res) => {
    const channelId = parseInt(req.params.id);
    const { data: channel } = await supabase.from('server_channels').select('server_id').eq('id', channelId).single();
    if (!channel) return res.status(404).json({ error: 'Introuvable' });
    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', channel.server_id).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });
    await supabase.from('server_channels').delete().eq('id', channelId);
    res.json({ success: true });
});

// Créer un rôle (owner only)
app.post('/api/servers/:id/roles', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const { name, color } = req.body;
    if (!name) return res.status(400).json({ error: 'Nom requis' });

    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });

    const { data: role, error } = await supabase.from('server_roles')
        .insert({ server_id: serverId, name, color: color || '#94a3b8' })
        .select().single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, role });
});

// Supprimer un rôle (owner only)
app.post('/api/roles/:id/delete', requireAuth, async (req, res) => {
    const roleId = parseInt(req.params.id);
    const { data: role } = await supabase.from('server_roles').select('server_id').eq('id', roleId).single();
    if (!role) return res.status(404).json({ error: 'Introuvable' });
    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', role.server_id).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });
    await supabase.from('server_roles').delete().eq('id', roleId);
    res.json({ success: true });
});

// Assigner un rôle à un membre (owner only)
app.post('/api/servers/:id/members/:userId/roles', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const targetUserId = parseInt(req.params.userId);
    const { roleId } = req.body;

    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });

    const { error } = await supabase.from('server_member_roles')
        .insert({ server_id: serverId, user_id: targetUserId, role_id: roleId });
    if (error) return res.status(400).json({ error: 'Rôle déjà assigné ou invalide' });
    res.json({ success: true });
});

// Retirer un rôle à un membre (owner only)
app.post('/api/servers/:id/members/:userId/roles/remove', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const targetUserId = parseInt(req.params.userId);
    const { roleId } = req.body;

    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });

    await supabase.from('server_member_roles')
        .delete().eq('server_id', serverId).eq('user_id', targetUserId).eq('role_id', roleId);
    res.json({ success: true });
});

// Expulser un membre (owner only)
app.post('/api/servers/:id/members/:userId/kick', requireAuth, async (req, res) => {
    const serverId = parseInt(req.params.id);
    const targetUserId = parseInt(req.params.userId);

    const { data: server } = await supabase.from('servers').select('owner_id').eq('id', serverId).single();
    if (!server || server.owner_id !== req.session.userId) return res.status(403).json({ error: 'Non autorisé' });
    if (targetUserId === req.session.userId) return res.status(400).json({ error: 'Impossible de s\'expulser soi-même' });

    await supabase.from('server_members').delete().eq('server_id', serverId).eq('user_id', targetUserId);
    res.json({ success: true });
});

// ========== DÉMARRAGE ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ KaliNet sur http://0.0.0.0:${PORT}`);
});

// ========== ANTI COLD START (ping toutes les 5 min) ==========
if (process.env.NODE_ENV === 'production' && process.env.APP_URL) {
    setInterval(() => {
        fetch(process.env.APP_URL).catch(() => {});
    }, 5 * 60 * 1000);
}
