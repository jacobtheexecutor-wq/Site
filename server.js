#!/usr/bin/env node
// ============================================================================
//  Vaultix production server (used on Render).
//      node shop-site/server.js
//
//  Serves the site plus the API (api/market.js, api/stripe-webhook.js) from one
//  Node process. Settings come from environment variables:
//    PORT                                                 set by Render automatically
//    UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN    database (required for real use)
//    MARKET_ADMIN_KEY                                     Staff page password
//    STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET            payments
//    SITE_URL                                             optional, e.g. https://vaultix.onrender.com
//  Without the database settings the site still loads and runs in demo mode.
//
//  shop-site/dev-server.js reuses createServer() with a fake database and fake Stripe.
// ============================================================================
require('dotenv').config()

const http = require('http')
const fs = require('fs')
const path = require('path')

const { createSecureApp } = require('./src/app')

const ROOT = __dirname
const HTML_ROOT = path.join(ROOT, 'src', 'html')
const secureApp = createSecureApp()
const MAX_BODY = 1024 * 1024 // 1 MB: listing pictures are ~270 KB at most
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.ico': 'image/x-icon', '.md': 'text/plain; charset=utf-8',
}
// Files that exist in shop-site/ but must never be served (shop-site/api/ holds Vercel entry points)
const PRIVATE = new Set(['server.js', 'dev-server.js'])

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('X-Frame-Options', 'DENY')
}

function serveStatic(req, res, u) {
  let rel
  try { rel = u.pathname === '/' ? 'index.html' : decodeURIComponent(u.pathname.slice(1)) } catch { rel = '' }

  let file = path.resolve(ROOT, rel)
  if (u.pathname === '/') {
    file = path.join(HTML_ROOT, 'index.html')
  } else if (u.pathname.startsWith('/assets/')) {
    file = path.resolve(ROOT, u.pathname.slice(1))
  } else if (u.pathname.endsWith('.html')) {
    file = path.join(HTML_ROOT, path.basename(u.pathname))
  }

  const name = path.basename(file)
  const top = rel.split(/[\\/]/)[0]
  if (!rel || !file.startsWith(ROOT + path.sep) || name.startsWith('.') || PRIVATE.has(name) || top === 'api' || rel.split(/[\\/]/).some((p) => p.startsWith('.'))) {
    res.statusCode = 404; return res.end('Not found')
  }
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.statusCode = 404; return res.end('Not found') }
    res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream')
    res.setHeader('Cache-Control', file.endsWith('.html') ? 'no-cache' : 'public, max-age=300')
    if (req.method === 'HEAD') return res.end()
    fs.createReadStream(file).pipe(res)
  })
}

function serveNewApp(req, res, u) {
  if (u.pathname === '/new' || u.pathname === '/new/') {
    const file = path.resolve(ROOT, 'new', 'index.html')
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.setHeader('Cache-Control', 'no-cache')
    if (req.method === 'HEAD') return res.end()
    return fs.createReadStream(file).pipe(res)
  }

  if (u.pathname.startsWith('/new/')) {
    const rel = decodeURIComponent(u.pathname.slice('/new/'.length)) || 'index.html'
    const base = path.resolve(ROOT, 'new')
    const file = path.resolve(base, rel)
    const name = path.basename(file)
    const allowed = file.startsWith(base + path.sep) || file === base
    if (!allowed || name.startsWith('.') || rel.split(/[\\/]/).some((p) => p.startsWith('.'))) {
      res.statusCode = 404; return res.end('Not found')
    }
    fs.stat(file, (e, st) => {
      if (e || !st.isFile()) { res.statusCode = 404; return res.end('Not found') }
      res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream')
      res.setHeader('Cache-Control', file.endsWith('.html') ? 'no-cache' : 'public, max-age=300')
      if (req.method === 'HEAD') return res.end()
      fs.createReadStream(file).pipe(res)
    })
    return
  }
}

// Small Vercel-style helpers so api/market.js runs unchanged.
function runMarket(market, req, res, u) {
  let size = 0
  const chunks = []
  req.on('data', (c) => {
    size += c.length
    if (size > MAX_BODY) { res.statusCode = 413; res.end('{"error":"Request too large"}'); req.destroy(); return }
    chunks.push(c)
  })
  req.on('end', () => {
    if (res.writableEnded) return
    const raw = Buffer.concat(chunks).toString('utf8')
    req.query = Object.fromEntries(u.searchParams)
    try { req.body = raw ? JSON.parse(raw) : {} } catch { req.body = {} }
    res.status = (c) => { res.statusCode = c; return res }
    res.json = (o) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)) }
    market(req, res)
  })
}

function createServer(opts = {}) {
  const market = require('./src/api/market.js')
  const webhook = require('./src/api/stripe-webhook.js')
  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://localhost')
    securityHeaders(res)
    try {
      if (opts.extraRoutes && (await opts.extraRoutes(req, res, u)) !== false) return
      if (u.pathname === '/api/stripe-webhook') return webhook(req, res)
      if (u.pathname === '/api/market') return runMarket(market, req, res, u)
      if (u.pathname === '/healthz' || (u.pathname.startsWith('/api/') && !u.pathname.startsWith('/api/market') && !u.pathname.startsWith('/api/stripe-webhook'))) {
        secureApp.handle(req, res)
        return
      }
      if (u.pathname.startsWith('/new')) return serveNewApp(req, res, u)
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.statusCode = 405; return res.end() }
      return serveStatic(req, res, u)
    } catch (e) {
      console.error(e)
      if (!res.headersSent) res.statusCode = 500
      res.end('Server error')
    }
  })
}

module.exports = { createServer }

const app = createSecureApp()

if (require.main === module) {
  const port = Number(process.env.PORT || 3000)
  const missing = ['MARKET_ADMIN_KEY', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'].filter((k) => !process.env[k])
  if (!(process.env.REDIS_URL || process.env.UPSTASH_REDIS_URL || process.env.KV_REST_API_URL)) missing.unshift('REDIS_URL (or UPSTASH_REDIS_URL / KV_REST_API_URL)')
  app.listen(port, () => {
    console.log(`AccountBay running on port ${port}`)
    if (missing.length) console.log(`Not set yet: ${missing.join(', ')} — the site runs in demo mode until the database is set, and payments need the Stripe keys.`)
  })
}

module.exports = app
