const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const { globalLimiter, authLimiter, walletLimiter } = require('./rateLimit');
const { createUser, findUserByEmail, getUserById, updateUser, addWalletDeposit, sanitizeUser, readUsers } = require('./db');
const { SESSION_COOKIE, SESSION_TTL_MS, createSession, getSessionUser, destroySession } = require('./auth');

function createSecureApp() {
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          baseUri: ["'self'"],
          objectSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
        },
      },
    })
  );

  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  app.use(globalLimiter);

  const ROOT = path.resolve(__dirname, '..');
  const HTML_ROOT = path.join(ROOT, 'src', 'html');
  app.use('/assets', express.static(path.join(ROOT, 'assets')));
  app.get(['/', '/index.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'index.html')));
  app.get(['/admin', '/admin.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'admin.html')));
  app.get(['/account', '/account.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'account.html')));
  app.get(['/listings', '/listings.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'listings.html')));
  app.get(['/account-settings', '/account-settings.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'account-settings.html')));
  app.get(['/profile', '/profile.html'], (_req, res) => res.sendFile(path.join(HTML_ROOT, 'profile.html')));

  const requireAuth = (req, res, next) => {
    const token = req.cookies[SESSION_COOKIE];
    if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });

    const user = getSessionUser(token);
    if (!user) return res.status(401).json({ error: 'Your session has expired. Please sign in again.' });

    req.user = user;
    next();
  };

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, service: 'AccountBay' });
  });

  app.get('/api/profile/:id', async (req, res) => {
    const user = await getUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: { ...user, email: user.email || '' } });
  });

  app.post('/api/auth/signup', authLimiter, async (req, res) => {
    const { name, email, password } = req.body || {};

    if (!name || String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    }

    const normalizedEmail = String(email || '').trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    if (await findUserByEmail(normalizedEmail)) {
      return res.status(409).json({ error: 'An account already exists with this email address.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await createUser({
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      avatarUrl: '',
      role: 'user',
      profile: { emailVerified: true },
    });

    const token = createSession(user.id);
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: SESSION_TTL_MS,
      path: '/',
    });

    return res.status(201).json({ user: sanitizeUser(user), message: 'Account created successfully.' });
  });

  app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: 'Please provide your email and password.' });
    }

    const user = await findUserByEmail(normalizedEmail);
    if (!user) return res.status(401).json({ error: 'No account matches that email address.' });

    const passwordMatches = await bcrypt.compare(String(password), user.passwordHash);
    if (!passwordMatches) return res.status(401).json({ error: 'Incorrect password.' });

    const token = createSession(user.id);
    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: SESSION_TTL_MS,
      path: '/',
    });

    return res.json({ user: sanitizeUser(user), message: 'Signed in successfully.' });
  });

  app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) destroySession(token);
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    return res.json({ ok: true, message: 'Signed out.' });
  });

  app.get('/api/auth/me', requireAuth, async (req, res) => {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ user: sanitizeUser(user) });
  });

  app.get('/api/wallet', requireAuth, async (req, res) => {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    return res.json({ wallet: user.wallet || { balance: 0, history: [] } });
  });

  app.post('/api/wallet/deposit', walletLimiter, requireAuth, async (req, res) => {
    const userId = req.user.id;
    const amount = Number(req.body?.amount);
    const method = String(req.body?.method || 'bank').trim();
    const sourceReference = String(req.body?.sourceReference || '').trim();

    if (!Number.isFinite(amount) || amount < 5 || amount > 2000) {
      return res.status(400).json({ error: 'Deposit amount must be between $5 and $2,000.' });
    }

    if (!['bank', 'crypto', 'card'].includes(method.toLowerCase())) {
      return res.status(400).json({ error: 'Unsupported deposit method.' });
    }

    const updated = await addWalletDeposit(userId, {
      amount,
      method: method.toLowerCase(),
      sourceReference: sourceReference.slice(0, 128) || 'manual-deposit',
    });

    if (!updated) return res.status(500).json({ error: 'Unable to process wallet deposit.' });

    return res.json({ message: 'Deposit processed successfully.', wallet: updated.wallet });
  });

  app.patch('/api/account/settings', requireAuth, async (req, res) => {
    const { name, username, email, bio, location, avatarUrl, theme, age } = req.body || {};
    const allowedTheme = ['light', 'dark', 'midnight'];
    const allowedEmail = String(email || '').trim().toLowerCase();
    const cleanUsername = username !== undefined ? String(username || '').trim().replace(/\s+/g, '') : undefined;
    const cleanAge = age !== undefined ? Number(age) : undefined;

    if (name !== undefined && String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Display name must be at least 2 characters.' });
    }

    if (cleanUsername !== undefined && cleanUsername && cleanUsername.length < 2) {
      return res.status(400).json({ error: 'Username must be at least 2 characters.' });
    }

    if (cleanAge !== undefined && (!Number.isFinite(cleanAge) || cleanAge < 13 || cleanAge > 120)) {
      return res.status(400).json({ error: 'Age must be between 13 and 120.' });
    }

    if (allowedEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(allowedEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    const existingUser = allowedEmail ? await findUserByEmail(allowedEmail) : null;
    if (existingUser && existingUser.id !== req.user.id) {
      return res.status(409).json({ error: 'That email address is already in use.' });
    }

    if (theme && !allowedTheme.includes(String(theme))) {
      return res.status(400).json({ error: 'Unsupported theme.' });
    }

    const profile = {
      ...(req.user.profile || {}),
      username: cleanUsername !== undefined ? cleanUsername : (req.user.profile || {}).username || '',
      age: cleanAge !== undefined ? cleanAge : (req.user.profile || {}).age,
      bio: bio !== undefined ? String(bio || '').slice(0, 240) : (req.user.profile || {}).bio || '',
      location: location !== undefined ? String(location || '').slice(0, 80) : (req.user.profile || {}).location || '',
      theme: theme !== undefined ? String(theme) : (req.user.profile || {}).theme || 'dark',
      emailVerified: true,
    };

    const update = {
      name: name !== undefined ? String(name).trim() : undefined,
      email: email !== undefined ? allowedEmail : undefined,
      avatarUrl: avatarUrl !== undefined ? String(avatarUrl || '').trim() : undefined,
      profile,
    };

    const user = await updateUser(req.user.id, update);
    if (!user) return res.status(404).json({ error: 'User no longer exists.' });

    return res.json({ message: 'Profile updated.', user: sanitizeUser(user) });
  });

  app.patch('/api/auth/password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User no longer exists.' });

    if (user.passwordHash && (!currentPassword || typeof currentPassword !== 'string')) {
      return res.status(400).json({ error: 'Your current password is required.' });
    }

    if (user.passwordHash && !(await bcrypt.compare(String(currentPassword), user.passwordHash))) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }

    const passwordHash = await bcrypt.hash(String(newPassword), 10);
    const updated = await updateUser(user.id, { passwordHash });
    return res.json({ message: 'Password updated.', user: sanitizeUser(updated) });
  });

  app.post('/api/auth/reset-password', async (req, res) => {
    const { emailOrUsername } = req.body || {};
    const value = String(emailOrUsername || '').trim();
    if (!value) return res.status(400).json({ error: 'Enter your email or username.' });

    const users = await readUsers();
    const user = await findUserByEmail(value) || users.find((item) => {
      const userName = String(item.name || '').trim().toLowerCase();
      const username = String(item.profile?.username || '').trim().toLowerCase();
      return userName === value.toLowerCase() || username === value.toLowerCase();
    });

    if (!user || !user.email) {
      return res.json({ ok: true, message: 'If an account matches, a reset link has been sent.' });
    }

    return res.json({ ok: true, message: 'If an account matches, a reset link has been sent.' });
  });

  app.get('/api/profile/me', requireAuth, async (req, res) => {
    const user = await getUserById(req.user.id);
    return res.json({ user: sanitizeUser(user) });
  });

  return app;
}

module.exports = { createSecureApp };
