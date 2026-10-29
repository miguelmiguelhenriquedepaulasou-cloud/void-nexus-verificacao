
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const {
  BASE_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  VERIFIED_ROLE_ID,
  SESSION_SECRET
} = process.env;

// Confere se as configurações necessárias existem
const required = {
  BASE_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  VERIFIED_ROLE_ID,
  SESSION_SECRET
};

const missing = Object.entries(required)
  .filter(([, value]) => !value)
  .map(([name]) => name);

if (missing.length > 0) {
  console.error('Faltam variáveis no Render:', missing.join(', '));
  process.exit(1);
}

// Configura a sessão
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000
  }
}));

// Carrega os arquivos da pasta public
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Página inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// Teste do servidor
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'Void Nexus Verification'
  });
});

// Inicia a verificação pelo Discord
app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/callback`,
    response_type: 'code',
    scope: 'identify',
    state
  });

  res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});

// Retorno do Discord após a autorização
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(
        'Você cancelou ou não autorizou a verificação. Volte ao site e tente novamente.'
      );
    }

    if (
      !code ||
      !state ||
      !req.session.oauthState ||
      state !== req.session.oauthState
    ) {
      return res.status(400).send(
        'A sessão de verificação expirou ou é inválida. Volte ao site e tente novamente.'
      );
    }

    delete req.session.oauthState;

    // Troca o código por um token de acesso do Discord
    const tokenResponse = await fetch(
      'https://discord.com/api/v10/oauth2/token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${BASE_URL}/auth/callback`
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Falha ao autorizar com o Discord.');
      return res.status(400).send(
        'Não foi possível autorizar sua conta. Volte ao site e tente novamente.'
      );
    }

    // Obtém os dados da conta autorizada
    const userResponse = await fetch(
      'https://discord.com/api/v10/users/@me',
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`
        }
      }
    );

    const user = await userResponse.json();

    if (!userResponse.ok || !user.id) {
      return res.status(400).send(
        'Não foi possível identificar sua conta Discord. Tente novamente.'
      );
    }

    // Confere se a pessoa já está no servidor
    const memberUrl =
      `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}` +
      `/members/${user.id}`;

    const memberResponse = await fetch(memberUrl, {
      headers: {
        Authorization: `Bot ${DISCORD_BOT_TOKEN}`
      }
    });

    if (memberResponse.status === 404) {
      return res.status(403).send(
        'Você precisa entrar no servidor Void Nexus antes de verificar sua conta.'
      );
    }

    if (!memberResponse.ok) {
      console.error(
        'Não foi possível conferir o membro. Status:',
        memberResponse.status
      );

      return res.status(502).send(
        'O bot não conseguiu conferir sua entrada no servidor. Tente novamente mais tarde.'
      );
    }

    // Adiciona o cargo de verificado
    const roleUrl =
      `${memberUrl}/roles/${VERIFIED_ROLE_ID}`;

    const roleResponse = await fetch(roleUrl, {
      method: 'PUT',
      headers: {
        Authorization: `Bot ${DISCORD_BOT_TOKEN}`
      }
    });

    if (!roleResponse.ok) {
      console.error(
        'Não foi possível atribuir o cargo. Status:',
        roleResponse.status
      );

      return res.status(502).send(
        'Sua conta foi reconhecida, mas não foi possível entregar o cargo. Verifique as permissões do bot e tente novamente.'
      );
    }

    // Sucesso
    const safeUsername = String(user.username || 'membro')
      .replace(/[&<>"']/g, '');

    return res.status(200).send(`
      <!doctype html>
      <html lang="pt-BR">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Verificação concluída</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: #101323;
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
          }
          main {
            max-width: 420px;
            margin: 20px;
            padding: 28px;
            border-radius: 18px;
            background: #1b2035;
          }
          h1 { color: #55e6a5; }
          p { line-height: 1.6; }
        </style>
      </head>
      <body>
        <main>
          <h1>Verificação concluída!</h1>
          <p>Olá, ${safeUsername}!</p>
          <p>Seu cargo de verificado foi atribuído no servidor Void Nexus.</p>
          <p>Você já pode voltar ao Discord.</p>
        </main>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('Erro durante a verificação:', err.message);

    return res.status(500).send(
      'Ocorreu um erro durante a verificação. Tente novamente mais tarde.'
    );
  }
});

// Inicia o servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Void Nexus Verification ativo na porta ${PORT}`);
});
