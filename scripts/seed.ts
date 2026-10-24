import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

// Import DB from src (ts-node --transpile-only resolves these at runtime)
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { db, initDB, STORAGE_DIR } = require('../src/db') as typeof import('../src/db');

const BCRYPT_ROUNDS = 12;

async function seed(): Promise<void> {
  initDB();

  console.log('=== TrustVault Seed ===\n');

  // ── Users ───────────────────────────────────────────────────────────────────
  const users: Array<{ username: string; password: string; role: string }> = [
    { username: 'admin',   password: 'Admin1234!',  role: 'admin'  },
    { username: 'owner1',  password: 'Owner1234!',  role: 'owner'  },
    { username: 'owner2',  password: 'Owner5678!',  role: 'owner'  },
    { username: 'viewer1', password: 'Viewer123!',  role: 'viewer' },
  ];

  const ids: Record<string, number> = {};

  for (const u of users) {
    const existing = db
      .prepare('SELECT id FROM users WHERE username = ?')
      .get(u.username) as { id: number } | undefined;

    if (existing) {
      console.log(`  [skip] user "${u.username}" already exists`);
      ids[u.username] = existing.id;
      continue;
    }

    const hash = await bcrypt.hash(u.password, BCRYPT_ROUNDS);
    const r = db
      .prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(u.username, hash, u.role);
    ids[u.username] = Number(r.lastInsertRowid);
    console.log(`  [create] user "${u.username}" (${u.role})`);
  }

  // ── Sample documents for owner1 ─────────────────────────────────────────────
  const docs: Array<{ name: string; category: string; content: string }> = [
    {
      name: 'Q1-Financial-Report.txt',
      category: 'finance',
      content: [
        'Q1 Financial Report — CONFIDENTIAL',
        '',
        'Revenue:  $1,200,000',
        'Expenses: $  820,000',
        'Net:      $  380,000',
        '',
        'Prepared by owner1. Distribution restricted.',
      ].join('\n'),
    },
    {
      name: 'Project-Alpha-Plan.txt',
      category: 'planning',
      content: [
        'Project Alpha — Internal Plan',
        '',
        'Phase 1: Research & Discovery   (Weeks 1-4)',
        'Phase 2: Design & Prototyping   (Weeks 5-8)',
        'Phase 3: Development            (Weeks 9-16)',
        'Phase 4: Testing & Launch       (Weeks 17-20)',
      ].join('\n'),
    },
  ];

  const docIds: string[] = [];

  for (const d of docs) {
    const existing = db
      .prepare('SELECT id FROM documents WHERE original_name = ? AND owner_id = ?')
      .get(d.name, ids['owner1']) as { id: string } | undefined;

    if (existing) {
      console.log(`  [skip] document "${d.name}" already exists`);
      docIds.push(existing.id);
      continue;
    }

    const docId = uuidv4();
    const storageName = `${uuidv4()}.txt`;
    const buf = Buffer.from(d.content, 'utf8');

    fs.writeFileSync(path.join(STORAGE_DIR, storageName), buf);

    db.prepare(
      `INSERT INTO documents (id, owner_id, storage_name, original_name, mime_type, category, size)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(docId, ids['owner1'], storageName, d.name, 'text/plain', d.category, buf.length);

    docIds.push(docId);
    console.log(`  [create] document "${d.name}" (owner: owner1, category: ${d.category})`);
  }

  // ── Grant viewer1 read-only access to the first doc ─────────────────────────
  if (docIds.length > 0) {
    db.prepare(`
      INSERT OR IGNORE INTO permissions (document_id, grantee_id, can_read, can_edit, granted_by)
      VALUES (?, ?, 1, 0, ?)
    `).run(docIds[0], ids['viewer1'], ids['owner1']);
    console.log(`  [grant] viewer1 → read-only on "${docs[0].name}"`);
  }

  // ── Confidential document for owner2 ────────────────────────────────────────
  const o2name = 'Owner2-Confidential.txt';
  const o2existing = db
    .prepare('SELECT id FROM documents WHERE original_name = ? AND owner_id = ?')
    .get(o2name, ids['owner2']) as { id: string } | undefined;

  if (!o2existing) {
    const o2id = uuidv4();
    const o2sn = `${uuidv4()}.txt`;
    const o2buf = Buffer.from(
      'CONFIDENTIAL — Owner2 eyes only.\nDo not distribute.',
      'utf8'
    );
    fs.writeFileSync(path.join(STORAGE_DIR, o2sn), o2buf);
    db.prepare(
      `INSERT INTO documents (id, owner_id, storage_name, original_name, mime_type, category, size)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(o2id, ids['owner2'], o2sn, o2name, 'text/plain', 'confidential', o2buf.length);
    console.log(`  [create] document "${o2name}" (owner: owner2)`);
  } else {
    console.log(`  [skip] document "${o2name}" already exists`);
  }

  console.log('\n=== Credentials ===');
  users.forEach(u => console.log(`  ${u.role.padEnd(6)}  ${u.username} / ${u.password}`));
  console.log('\nSeed complete.');
}

seed().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
