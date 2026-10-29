require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const crypto = require('node:crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;
const CALLBACK_URL = `${BASE_URL}/auth/callback`;

const missing = ['BASE_URL','DISCORD_CLIENT_ID','DISCORD_CLIENT_SECRET','DISCORD_BOT_TOKEN','DISCORD_GUILD_ID','VERIFIED_ROLE_ID','SESSION_SECRET'].filter(k => !process.env[k]);
if (missing.length) {
  console.error(`Faltam variáveis no .env: ${missing.join(', ')}`);
  process.exit(1);
}
if (!BASE_URL.startsWith('https://') && process.env.NODE_ENV === 'production') {
  console.error('Em produção, BASE_URL precisa começar com https://');
  process.exit(1);
}

app.disable('x-powered-by');
// A hospedagem normalmente termina HTTPS num proxy reverso.
if (BASE_URL.startsWith('https://')) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'https://cdn.discordapp.com', 'data:'],
  formAction: ["'self'"], frameAncestors: ["'none'"], upgradeInsecureRequests: null
} }}));
app.use(session({
  name: 'voidnexus.sid', secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: BASE_URL.startsWith('https://'), maxAge: 10 * 60 * 1000 }
}));
app.use(express.static('public'));

async function discordApi(path, options = {}) {
  const response = await fetch(`https://discord.com/api/v10${path}`, {
    ...options,
    headers: { Authorization: `Bot ${BOT_TOKEN}`, ...(options.headers || {}) }
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    const err = new Error(`Discord API ${response.status}: ${detail.slice(0, 300)}`);
    err.status = response.status;
    throw err;
  }
  if (response.status === 204) return null;
  return response.json();
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'Void Nexus Verification' }));

app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    response_type: 'code',
    scope: 'identify',
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(page('Verificação cancelada', 'Você cancelou a autorização do Discord. Volte ao servidor e tente novamente.', true));
  if (!code || !state || !req.session.oauthState || state !== req.session.oauthState) {
    return res.status(400).send(page('Não foi possível verificar', 'A sessão expirou ou não corresponde. Volte ao servidor e tente novamente.', true));
  }
  delete req.session.oauthState;
  try {
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code',
        code: String(code), redirect_uri: CALLBACK_URL
      })
    });
    if (!tokenResponse.ok) throw new Error('O Discord não aceitou a autorização. Confira Client ID, Secret e Redirect URI.');
    const oauth = await tokenResponse.json();
    const userResponse = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `${oauth.token_type} ${oauth.access_token}` }
    });
    if (!userResponse.ok) throw new Error('Não foi possível confirmar sua conta Discord.');
    const user = await userResponse.json();

    // Só atribui o cargo a quem já pertence ao servidor.
    try {
      await discordApi(`/guilds/${GUILD_ID}/members/${user.id}`);
    } catch (e) {
      if (e.status === 404) return res.status(403).send(page('Entre no servidor primeiro', 'Você precisa entrar no servidor Void Nexus antes de concluir a verificação.', true));
      throw e;
    }
    await discordApi(`/guilds/${GUILD_ID}/members/${user.id}/roles/${VERIFIED_ROLE_ID}`, { method: 'PUT' });
    req.session.verifiedName = user.global_name || user.username || 'membro';
    return res.send(page('Verificação concluída!', `Tudo certo, ${escapeHtml(req.session.verifiedName)}. O cargo de membro verificado foi aplicado. Se os canais não aparecerem imediatamente, aguarde alguns segundos e reabra o Discord.`, false));
  } catch (e) {
    console.error('Erro de verificação:', e.message);
    return res.status(500).send(page('Erro na verificação', 'Não foi possível concluir agora. Avise a equipe do Void Nexus. Se você administra o bot, confira as variáveis do .env e se o bot tem a permissão Gerenciar Cargos.', true));
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function page(title, message, isError) {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101a35"><title>${escapeHtml(title)} · Void Nexus</title><link rel="stylesheet" href="/style.css"></head><body><main class="card"><div class="logo">VN</div><p class="eyebrow">VOID NEXUS</p><h1>${escapeHtml(title)}</h1><p class="message">${message}</p><a class="button" href="/">Voltar ao início</a>${isError ? '<p class="small">Nenhuma senha ou token do Discord é solicitado neste site.</p>' : '<p class="small">Você pode fechar esta página e voltar ao Discord.</p>'}</main></body></html>`;
}

app.listen(PORT, () => console.log(`Void Nexus Verification ativo na porta ${PORT}`));
