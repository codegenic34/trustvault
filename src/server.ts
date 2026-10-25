import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import path from 'path';
import fs from 'fs';
import { db, initDB, STORAGE_DIR } from './db';
import { seed } from '../scripts/seed';
import authRoutes from './routes/auth';
import documentRoutes from './routes/documents';
import permissionRoutes from './routes/permissions';
import adminRoutes from './routes/admin';

// Initialise DB (creates tables + triggers) before anything else
initDB();

// ── Startup: Ensure storage directory exists ──────────────────────────────────
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// ── Startup: Run seed if the users table is empty ────────────────────────────
let seedPromise: Promise<void> | null = null;
try {
  const row = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number } | undefined;
  if (!row || row.count === 0) {
    console.log('Users table empty on startup; running seed...');
    seedPromise = seed()
      .then(() => {
        console.log('Database seeded successfully.');
        seedPromise = null;
      })
      .catch((err) => {
        console.error('Failed to seed database on startup:', err);
        seedPromise = null;
      });
  }
} catch (err) {
  console.error('Error checking users count on startup:', err);
}

const app = express();
const PORT = parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';

// Trust one layer of proxy (needed for Render's HTTPS reverse proxy & rate-limiter IP detection)
app.set('trust proxy', 1);

// Await startup seed completion if actively running before handling incoming requests
app.use(async (_req, _res, next) => {
  if (seedPromise) {
    try {
      await seedPromise;
    } catch {}
  }
  next();
});

// ── Security headers ──────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:      ["'self'"],
        scriptSrc:       ["'self'", 'https://cdn.tailwindcss.com'],
        styleSrc:        ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://fonts.googleapis.com'],
        imgSrc:          ["'self'", 'data:'],
        connectSrc:      ["'self'"],
        fontSrc:         ["'self'", 'https://fonts.gstatic.com'],
        objectSrc:       ["'none'"],
        frameAncestors:  ["'none'"],
        baseUri:         ["'self'"],
        formAction:      ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// ── Body parsers ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// ── Never serve storage directory publicly ────────────────────────────────────
app.use('/storage', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Static files — only the /public directory ─────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'] }));

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api', authRoutes);
app.use('/api/documents', documentRoutes);

// permissions router uses mergeParams:true to inherit :id from the parent
// Mount directly — Express will pass :id because mergeParams is set in the router
app.use('/api/documents/:id/permissions', permissionRoutes);

app.use('/api/audit', adminRoutes);
app.use('/api/admin', adminRoutes);

// ── SPA fallback (non-API routes serve index.html) ───────────────────────────
app.get(/^(?!\/api).*$/, (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use(
  (
    err: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
);

app.listen(PORT, HOST, () => {
  console.log(`TrustVault listening on http://${HOST}:${PORT}`);
  console.log(`Run "npm run seed" to create default users if this is a fresh install.`);
});

export default app;
