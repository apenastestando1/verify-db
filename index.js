require('dotenv').config();

const { Client, GatewayIntentBits, PermissionsBitField } = require('discord.js');
const express = require('express');
const session = require('express-session');
const path = require('path');
const { connect, close } = require('./db');

const VERIFY_ROLE_ID = process.env.VERIFY_ROLE_ID || '1448108844407328859';

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers]
});

const app = express();

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

const requireAuth = (req, res, next) =>
  req.session.logged ? next() : res.redirect('/login');

app.use(express.static(path.join(__dirname, 'public')));

let users;
let verifications;

async function assignVerifyRole(member) {
  if (!VERIFY_ROLE_ID || !member) return false;
  try {
    if (member.roles.cache.has(VERIFY_ROLE_ID)) return false;
    const role = await member.guild.roles.fetch(VERIFY_ROLE_ID).catch(() => null);
    if (!role) return false;
    await member.roles.add(role);
    return true;
  } catch (err) {
    console.error('Erro ao atribuir cargo:', err.message);
    return false;
  }
}

app.get('/login', (req, res) =>
  res.sendFile(path.join(__dirname, 'public/login.html')));

app.post('/login', (req, res) => {
  const ok = req.body.password && req.body.password === process.env.DASHBOARD_PASSWORD;
  if (!ok) return res.redirect('/login?error=1');
  req.session.logged = true;
  res.redirect('/');
});

app.get('/logout', (req, res) =>
  req.session.destroy(() => res.redirect('/login')));

app.get('/', requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public/index.html')));

app.get('/callback', (req, res) =>
  res.sendFile(path.join(__dirname, 'public/callback.html')));

app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const guilds = client.guilds.cache.map(g => ({
      id: g.id,
      name: g.name,
      memberCount: g.memberCount
    }));

    const totalMembers = guilds.reduce((a, b) => a + b.memberCount, 0);
    const totalVerifiedUsers = await users.countDocuments();

    res.json({
      botTag: client.user?.tag || '—',
      botId: client.user?.id || '',
      ping: client.ws.ping,
      uptime: Math.floor(process.uptime()),
      guildCount: guilds.length,
      totalMembers,
      totalVerifiedUsers,
      guilds
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/invite', requireAuth, (req, res) => {
  const permissions = new PermissionsBitField([
    PermissionsBitField.Flags.ViewChannel,
    PermissionsBitField.Flags.SendMessages,
    PermissionsBitField.Flags.ReadMessageHistory,
    PermissionsBitField.Flags.CreateInstantInvite,
    PermissionsBitField.Flags.ManageRoles
  ]).bitfield.toString();

  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    scope: 'bot applications.commands',
    permissions
  });

  res.json({ url: `https://discord.com/oauth2/authorize?${params}` });
});

app.get('/api/verify-url', requireAuth, (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    response_type: 'code',
    scope: 'identify guilds.join',
    prompt: 'consent'
  });

  res.json({ url: `https://discord.com/oauth2/authorize?${params}` });
});

app.get('/oauth/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error === 'access_denied') {
    return res.redirect('/callback?status=cancelled');
  }
  if (error) {
    return res.redirect('/callback?status=error&message=' +
      encodeURIComponent(String(error_description || error)));
  }
  if (!code) {
    return res.redirect('/callback?status=error&message=' +
      encodeURIComponent('Código de autorização ausente.'));
  }

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.REDIRECT_URI
      })
    });

    const token = await tokenRes.json();
    if (!token.access_token) {
      return res.redirect('/callback?status=error&message=' +
        encodeURIComponent('Falha ao obter token de acesso.'));
    }

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    const user = await userRes.json();

    if (!user.id) {
      return res.redirect('/callback?status=error&message=' +
        encodeURIComponent('Falha ao obter dados do usuário.'));
    }

    await users.updateOne(
      { id: user.id },
      {
        $set: {
          username: user.username,
          access_token: token.access_token,
          refresh_token: token.refresh_token,
          added_at: Date.now()
        }
      },
      { upsert: true }
    );

    for (const guild of client.guilds.cache.values()) {
      const member = await guild.members.fetch(user.id).catch(() => null);
      if (member) await assignVerifyRole(member);
    }

    res.redirect('/callback?status=success&user=' + encodeURIComponent(user.username));
  } catch (err) {
    res.redirect('/callback?status=error&message=' + encodeURIComponent(err.message));
  }
});

app.post('/api/add', requireAuth, async (req, res) => {
  const input = String(req.body.input || '').trim();
  const guildId = String(req.body.guildId || '').trim();

  if (!input || !guildId)
    return res.status(400).json({ error: 'input e guildId são obrigatórios' });

  if (!/^\d{17,20}$/.test(guildId))
    return res.status(400).json({ error: 'ID de servidor inválido' });

  let guild;
  try {
    guild = await client.guilds.fetch(guildId);
  } catch {
    return res.status(404).json({ error: 'Servidor não encontrado ou bot não está nele' });
  }

  let ids = [];

  if (/^\d{1,6}$/.test(input)) {
    const n = Math.min(parseInt(input, 10), 500);
    if (n <= 0) return res.status(400).json({ error: 'Quantidade inválida' });

    const sampled = await users.aggregate([{ $sample: { size: n } }]).toArray();
    ids = sampled.map(u => u.id);

    if (!ids.length)
      return res.status(400).json({ error: 'Banco vazio — ninguém verificado ainda' });
  } else {
    ids = input.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
    const invalids = ids.filter(id => !/^\d{17,20}$/.test(id));
    if (invalids.length)
      return res.status(400).json({ error: 'IDs inválidos: ' + invalids.join(', ') });
  }

  const results = [];

  for (const userId of ids) {
    const user = await users.findOne({ id: userId });
    if (!user) {
      results.push({ userId, success: false, error: 'Não está no banco de dados' });
      continue;
    }

    try {
      let member = await guild.members.fetch(userId).catch(() => null);

      if (!member) {
        await guild.members.add(userId, { accessToken: user.access_token });
        member = await guild.members.fetch(userId).catch(() => null);
      }

      await verifications.insertOne({
        user_id: userId,
        guild_id: guildId,
        added_at: Date.now()
      });

      if (member) await assignVerifyRole(member);

      results.push({
        userId,
        username: user.username,
        success: true,
        alreadyMember: !member ? false : undefined
      });
    } catch (err) {
      results.push({ userId, username: user.username, success: false, error: err.message });
    }
  }

  res.json({ guildName: guild.name, results });
});

app.get('/ping', (req, res) => res.status(200).send('pong'));

client.once('ready', () => console.log(`✅ Bot online como ${client.user.tag}`));

client.on('guildMemberAdd', async member => {
  if (!users) return;
  try {
    const user = await users.findOne({ id: member.id });
    if (!user) return;
    await assignVerifyRole(member);
  } catch (err) {
    console.error('Erro em guildMemberAdd:', err.message);
  }
});

async function main() {
  const db = await connect();
  users = db.users;
  verifications = db.verifications;
  console.log('✅ MongoDB conectado');

  await client.login(process.env.BOT_TOKEN);

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => console.log(`🌐 Web em :${PORT}`));
}

main().catch(err => {
  console.error('❌ Falha ao iniciar:', err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  await close();
  process.exit(0);
});
