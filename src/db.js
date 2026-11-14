require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('redis');

const DATA_DIR = path.join(__dirname, '..', '.data');
const DATA_FILE = path.join(DATA_DIR, 'users.json');
const USERS_KEY = 'accountbay:users';
const LISTINGS_KEY = 'accountbay:listings';

let redisClient = null;

function getRedisClient() {
  const redisUrl = process.env.REDIS_URL || process.env.UPSTASH_REDIS_URL || process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  if (!redisUrl) return null;
  if (!redisClient) {
    redisClient = createClient({ url: redisUrl });
    redisClient.on('error', (err) => console.warn('Redis warning:', err.message));
    redisClient.connect().catch(() => {
      redisClient = null;
    });
  }
  return redisClient;
}

async function readUsers() {
  const client = getRedisClient();
  if (client && client.isReady) {
    const raw = await client.get(USERS_KEY);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  }

  ensureStore();
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed.users) ? parsed.users : [];
  } catch {
    return [];
  }
}

async function writeUsers(users) {
  const client = getRedisClient();
  if (client && client.isReady) {
    await client.set(USERS_KEY, JSON.stringify(users));
    return;
  }

  ensureStore();
  fs.writeFileSync(DATA_FILE, JSON.stringify({ users }, null, 2));
}

async function readListings() {
  const client = getRedisClient();
  if (client && client.isReady) {
    const raw = await client.get(LISTINGS_KEY);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  }
  return [];
}

async function writeListings(listings) {
  const client = getRedisClient();
  if (client && client.isReady) {
    await client.set(LISTINGS_KEY, JSON.stringify(listings));
    return;
  }
}

function ensureStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [] }, null, 2));
  }
}

async function findUserByEmail(email) {
  const users = await readUsers();
  return users.find((user) => user.email && user.email.toLowerCase() === String(email).toLowerCase()) || null;
}

async function getUserById(id) {
  const users = await readUsers();
  return users.find((user) => user.id === id) || null;
}

async function createUser(data) {
  const users = await readUsers();
  const user = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    wallet: { balance: 0, history: [] },
    ...data,
  };
  users.push(user);
  await writeUsers(users);
  return user;
}

async function updateUser(id, patch) {
  const users = await readUsers();
  const index = users.findIndex((user) => user.id === id);
  if (index === -1) return null;

  const merged = { ...users[index], ...patch };
  if (patch.profile) {
    merged.profile = { ...(users[index].profile || {}), ...patch.profile };
  }

  if (patch.name !== undefined) merged.name = String(patch.name).trim();
  if (patch.email !== undefined) merged.email = String(patch.email).trim().toLowerCase();
  if (patch.avatarUrl !== undefined) merged.avatarUrl = String(patch.avatarUrl).trim();

  users[index] = merged;
  await writeUsers(users);
  return merged;
}

async function addWalletDeposit(userId, deposit) {
  const users = await readUsers();
  const index = users.findIndex((user) => user.id === userId);
  if (index === -1) return null;

  const amount = Number(deposit.amount || 0);
  users[index].wallet = users[index].wallet || { balance: 0, history: [] };
  users[index].wallet.balance = Number((users[index].wallet.balance || 0) + amount).toFixed(2);
  users[index].wallet.history = [
    ...(users[index].wallet.history || []),
    {
      id: crypto.randomUUID(),
      type: 'deposit',
      amount,
      method: deposit.method || 'bank',
      sourceReference: deposit.sourceReference || 'manual-deposit',
      createdAt: new Date().toISOString(),
    },
  ];

  await writeUsers(users);
  return users[index];
}

async function saveListing(listing) {
  const listings = await readListings();
  const existingIndex = listings.findIndex((item) => item.id === listing.id);
  if (existingIndex >= 0) listings[existingIndex] = listing;
  else listings.push(listing);
  await writeListings(listings);
  return listing;
}

async function getListings() {
  return readListings();
}

function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

module.exports = {
  createUser,
  findUserByEmail,
  getUserById,
  updateUser,
  addWalletDeposit,
  saveListing,
  getListings,
  readUsers,
  sanitizeUser,
};
