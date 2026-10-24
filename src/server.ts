import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import path from 'path';
import { initDB } from './db';
import authRoutes from './routes/auth';
import documentRoutes from './routes/documents';
import permissionRoutes from './routes/permissions';
import adminRoutes from './routes/admin';

// Initialise DB (creates tables + triggers) before anything else
initDB();

const app = express();
const PORT = parseInt(process.env.PORT ?? '3000', 10);

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

// Trust one layer of proxy (needed for rate-limiter IP detection on typical setups)
app.set('trust proxy', 1);

// ── Static files — only the /public directory ─────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api', authRoutes);
app.use('/api/documents', documentRoutes);

// permissions router uses mergeParams:true to inherit :id from the parent
// Mount directly — Express will pass :id because mergeParams is set in the router
app.use('/api/documents/:id/permissions', permissionRoutes);

app.use('/api/audit', adminRoutes);

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

app.listen(PORT, () => {
  console.log(`TrustVault listening on http://localhost:${PORT}`);
  console.log(`Run "npm run seed" to create default users if this is a fresh install.`);
});

export default app;
