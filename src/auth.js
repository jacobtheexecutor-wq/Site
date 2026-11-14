const SESSION_COOKIE = 'accountbay_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const sessions = new Map();

function createSession(userId) {
  const token = `${Date.now()}:${Math.random().toString(36).slice(2)}:${userId}`;
  sessions.set(token, { userId, expiresAt: Date.now() + SESSION_TTL_MS });
  return token;
}

function getSessionUser(token) {
  if (!token || !sessions.has(token)) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { id: session.userId };
}

function destroySession(token) {
  if (token) sessions.delete(token);
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_MS,
  createSession,
  getSessionUser,
  destroySession,
};
