require('dotenv').config();
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function resetAdmin() {
    const username = 'Kalinux';
    const password = 'azertydox1234';
    const hashedPassword = await bcrypt.hash(password, 10);

    // Vérifie si le compte existe
    const { data: existing } = await supabase
        .from('users')
        .select('id')
        .eq('username', username)
        .single();

    if (existing) {
        // Met à jour le mot de passe + remet admin
        const { error } = await supabase
            .from('users')
            .update({ password: hashedPassword, is_admin: 1, rank: 'admin' })
            .eq('username', username);
        if (error) console.error('Erreur update:', error);
        else console.log(`✅ Mot de passe de ${username} mis à jour`);
    } else {
        // Crée le compte admin
        const { error } = await supabase
            .from('users')
            .insert({ username, password: hashedPassword, is_admin: 1, rank: 'admin' });
        if (error) console.error('Erreur création:', error);
        else console.log(`✅ Compte admin ${username} créé`);
    }

    process.exit(0);
}

resetAdmin();
