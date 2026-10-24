import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import type { SQLInputValue } from 'node:sqlite';
import { db, STORAGE_DIR } from '../db';
import { requireAuth } from '../auth';
import { verifyCsrf } from '../middleware/security';
import { authorize } from '../authorize';
import { writeAudit } from '../audit';

const router = Router();
router.use(requireAuth);

// ── File validation constants ────────────────────────────────────────────────

const ALLOWED_EXT = new Set(['pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx']);
const MAX_SIZE = 5 * 1024 * 1024; // 5 MB

const MAGIC: Record<string, number[]> = {
  pdf:  [0x25, 0x50, 0x44, 0x46],
  png:  [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  jpg:  [0xff, 0xd8, 0xff],
  jpeg: [0xff, 0xd8, 0xff],
  docx: [0x50, 0x4b, 0x03, 0x04],
};

const EXT_MIME: Record<string, string> = {
  pdf:  'application/pdf',
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  txt:  'text/plain',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};

function magicOk(buf: Buffer, ext: string): boolean {
  if (ext === 'txt') return true; // TXT has no universal magic bytes
  const expected = MAGIC[ext];
  if (!expected) return false;
  return expected.every((b, i) => buf[i] === b);
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_SIZE },
});

// ── Input schemas ────────────────────────────────────────────────────────────

const EditSchema = z.object({
  original_name: z.string().min(1).max(255).optional(),
  category: z
    .string()
    .max(64)
    .regex(/^[a-zA-Z0-9 _-]*$/)
    .optional(),
});

// ── POST /api/documents ─ Upload (owner only) ────────────────────────────────

router.post('/', verifyCsrf, upload.single('file'), (req: Request, res: Response) => {
  const user = req.user!;

  if (user.role !== 'owner') {
    writeAudit({
      actor_id: user.id,
      action: 'UPLOAD',
      outcome: 'DENY',
      detail: 'Upload attempted by non-owner',
      deny_reason: 'WRONG_ROLE',
    });
    res.status(403).json({ error: 'Only owners can upload documents' });
    return;
  }

  if (!req.file) {
    res.status(400).json({ error: 'No file provided' });
    return;
  }

  const origName = req.file.originalname;
  const ext = path.extname(origName).toLowerCase().replace('.', '');

  if (!ALLOWED_EXT.has(ext)) {
    writeAudit({
      actor_id: user.id,
      action: 'UPLOAD',
      outcome: 'DENY',
      detail: `Rejected extension: .${ext} for file: ${origName}`,
      deny_reason: 'NO_PERMISSION',
    });
    res.status(400).json({ error: 'File type not allowed' });
    return;
  }

  if (!magicOk(req.file.buffer, ext)) {
    writeAudit({
      actor_id: user.id,
      action: 'UPLOAD',
      outcome: 'DENY',
      detail: `Magic-byte mismatch for: ${origName}`,
      deny_reason: 'NO_PERMISSION',
    });
    res.status(400).json({ error: 'File content does not match declared extension' });
    return;
  }

  const rawCategory =
    typeof req.body.category === 'string' ? req.body.category.slice(0, 64) : '';
  if (rawCategory && !/^[a-zA-Z0-9 _-]*$/.test(rawCategory)) {
    res.status(400).json({ error: 'Invalid characters in category' });
    return;
  }

  const docId = uuidv4();
  const storageName = `${uuidv4()}.${ext}`;
  const storagePath = path.join(STORAGE_DIR, storageName);
  const mime = EXT_MIME[ext] ?? 'application/octet-stream';

  fs.writeFileSync(storagePath, req.file.buffer);

  db.prepare(`
    INSERT INTO documents (id, owner_id, storage_name, original_name, mime_type, category, size)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(docId, user.id, storageName, origName, mime, rawCategory, req.file.size);

  writeAudit({
    actor_id: user.id,
    action: 'UPLOAD',
    resource_id: docId,
    outcome: 'ALLOW',
    detail: `Uploaded: ${origName} (${req.file.size} bytes, category: ${rawCategory || 'none'})`,
  });

  res.status(201).json({
    document: {
      id: docId,
      original_name: origName,
      category: rawCategory,
      size: req.file.size,
      mime_type: mime,
    },
  });
});

// ── GET /api/documents ─ List / search (scoped) ──────────────────────────────

const SearchSchema = z.object({
  q:        z.string().max(128).optional(),
  name:     z.string().max(255).optional(),
  category: z.string().max(64).optional(),
  from:     z.string().max(30).optional(),
  to:       z.string().max(30).optional(),
});

router.get('/', (req: Request, res: Response) => {
  const user = req.user!;
  const parsed = SearchSchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters' });
    return;
  }
  const { q, name, category, from, to } = parsed.data;

  // Scoping: user sees only their own docs OR docs with an active can_read grant.
  // Admin has NO implicit access — treated the same as any other role here.
  const conditions: string[] = [
    'd.deleted = 0',
    '(d.owner_id = @uid OR p.can_read = 1)',
  ];
  const params: Record<string, SQLInputValue> = { uid: user.id };

  if (q) {
    conditions.push('(d.original_name LIKE @q_name OR d.category LIKE @q_cat)');
    params.q_name = `%${q}%`;
    params.q_cat  = `%${q}%`;
  }
  if (name) {
    conditions.push('d.original_name LIKE @name');
    params.name = `%${name}%`;
  }
  if (category) {
    conditions.push('d.category = @category');
    params.category = category;
  }
  if (from) {
    conditions.push('d.created_at >= @from');
    params.from = from;
  }
  if (to) {
    conditions.push('d.created_at <= @to');
    params.to = to;
  }

  const sql = `
    SELECT d.id,
           d.original_name,
           d.category,
           d.size,
           d.mime_type,
           d.created_at,
           u.username        AS owner_name,
           (d.owner_id = @uid)                                            AS is_owner,
           CASE WHEN d.owner_id = @uid THEN 1 ELSE COALESCE(p.can_read, 0) END AS can_read,
           CASE WHEN d.owner_id = @uid THEN 1 ELSE COALESCE(p.can_edit, 0) END AS can_edit
    FROM documents d
    JOIN users u ON u.id = d.owner_id
    LEFT JOIN permissions p
           ON p.document_id = d.id
          AND p.grantee_id  = @uid
          AND p.revoked_at IS NULL
    WHERE ${conditions.join(' AND ')}
    ORDER BY d.created_at DESC
  `;

  const documents = db.prepare(sql).all(params);
  res.json({ documents });
});

// ── GET /api/documents/:id/download ──────────────────────────────────────────

router.get('/:id/download', (req: Request, res: Response) => {
  const user = req.user!;
  const { id } = req.params;

  const authResult = authorize(user, 'download', id);

  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'DOWNLOAD',
      resource_id: id,
      outcome: 'DENY',
      detail: `Download denied for document ${id}`,
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  const doc = db
    .prepare(
      'SELECT storage_name, original_name FROM documents WHERE id = ? AND deleted = 0'
    )
    .get(id) as { storage_name: string; original_name: string } | undefined;

  if (!doc) {
    res.status(404).json({ error: 'Document not found' });
    return;
  }

  const filePath = path.join(STORAGE_DIR, doc.storage_name);
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: 'File not found on disk' });
    return;
  }

  writeAudit({
    actor_id: user.id,
    action: 'DOWNLOAD',
    resource_id: id,
    outcome: 'ALLOW',
    detail: `Downloaded: ${doc.original_name}`,
  });

  // Serve as attachment; never let browser inline-render (GEMINI Rule 5)
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${encodeURIComponent(doc.original_name)}"`
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.sendFile(filePath);
});

// ── PATCH /api/documents/:id ─ Edit metadata ─────────────────────────────────

router.patch('/:id', verifyCsrf, (req: Request, res: Response) => {
  const user = req.user!;
  const { id } = req.params;

  const authResult = authorize(user, 'edit_metadata', id);

  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'EDIT_METADATA',
      resource_id: id,
      outcome: 'DENY',
      detail: `Edit metadata denied for document ${id}`,
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  const parsed = EditSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid input', issues: parsed.error.flatten() });
    return;
  }

  const { original_name, category } = parsed.data;
  const fields: string[] = [];
  const values: (string | number)[] = [];

  if (original_name !== undefined) { fields.push('original_name = ?'); values.push(original_name); }
  if (category !== undefined)      { fields.push('category = ?');       values.push(category); }

  if (fields.length === 0) {
    res.status(400).json({ error: 'No fields to update' });
    return;
  }

  values.push(id);
  db.prepare(`UPDATE documents SET ${fields.join(', ')} WHERE id = ?`).run(...values);

  writeAudit({
    actor_id: user.id,
    action: 'EDIT_METADATA',
    resource_id: id,
    outcome: 'ALLOW',
    detail: `Updated: ${fields.join(', ')}`,
  });

  res.json({ message: 'Document updated' });
});

// ── DELETE /api/documents/:id ─ Soft-delete (owner only) ─────────────────────

router.delete('/:id', verifyCsrf, (req: Request, res: Response) => {
  const user = req.user!;
  const { id } = req.params;

  const authResult = authorize(user, 'delete', id);

  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'DELETE_DOCUMENT',
      resource_id: id,
      outcome: 'DENY',
      detail: `Delete denied for document ${id}`,
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  db.prepare('UPDATE documents SET deleted = 1 WHERE id = ?').run(id);

  writeAudit({
    actor_id: user.id,
    action: 'DELETE_DOCUMENT',
    resource_id: id,
    outcome: 'ALLOW',
    detail: `Document soft-deleted`,
  });

  res.json({ message: 'Document deleted' });
});

export default router;
