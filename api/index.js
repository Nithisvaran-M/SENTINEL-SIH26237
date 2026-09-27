import express from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument, rgb } from 'pdf-lib';

const app = express();
const RUNTIME = path.join('/tmp', 'sentinel-runtime');
const DIRS = ['keys', 'documents', 'ledger', 'temp', 'identities'];
for (const d of DIRS) fs.mkdirSync(path.join(RUNTIME, d), { recursive: true });

app.use(express.json({ limit: '12mb' }));
const upload = multer({
  dest: path.join(RUNTIME, 'temp'),
  limits: { fileSize: 20 * 1024 * 1024 }
});

const f = (...p) => path.join(RUNTIME, ...p);
const now = () => new Date().toISOString();
const sha256 = x => crypto.createHash('sha256').update(x).digest('hex');
const b64 = x => Buffer.from(x).toString('base64');
const unb64 = x => Buffer.from(x, 'base64');
const canonical = o => JSON.stringify(o, Object.keys(o).sort());
const writeJson = (p, o) => fs.writeFileSync(p, JSON.stringify(o, null, 2));
const readJson = (p, fallback) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fallback; } };

function keypair(type) {
  return crypto.generateKeyPairSync(type, { publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
}

function generatePQC(id) {
  const kem = keypair('ml-kem-768');
  const sig = keypair('ml-dsa-65');
  fs.writeFileSync(f('keys', `${id}.kem.private.pem`), kem.privateKey);
  fs.writeFileSync(f('keys', `${id}.kem.public.pem`), kem.publicKey);
  fs.writeFileSync(f('keys', `${id}.sig.private.pem`), sig.privateKey);
  fs.writeFileSync(f('keys', `${id}.sig.public.pem`), sig.publicKey);
  return { kemPublic: kem.publicKey, sigPublic: sig.publicKey };
}

function recipients() { return readJson(f('identities', 'recipients.json'), []); }
function saveRecipients(x) { writeJson(f('identities', 'recipients.json'), x); }
function documents() { return readJson(f('documents', 'documents.json'), []); }
function saveDocuments(x) { writeJson(f('documents', 'documents.json'), x); }

function ledgerBlocks() {
  return fs.readdirSync(f('ledger')).filter(x => x.endsWith('.json')).sort().map(x => readJson(f('ledger', x), null)).filter(Boolean);
}
function appendLedger(payload) {
  const blocks = ledgerBlocks();
  const prev = blocks.at(-1);
  const block = { index: blocks.length, timestamp: now(), previousHash: prev?.hash || 'GENESIS', payload };
  block.hash = sha256(canonical(block));
  writeJson(f('ledger', `${String(block.index).padStart(8, '0')}-${block.hash.slice(0, 16)}.json`), block);
  return block;
}
function verifyLedger() {
  const blocks = ledgerBlocks();
  let previous = 'GENESIS'; const problems = [];
  blocks.forEach((b, i) => {
    const copy = { index: b.index, timestamp: b.timestamp, previousHash: b.previousHash, payload: b.payload };
    if (b.index !== i || b.previousHash !== previous || sha256(canonical(copy)) !== b.hash) problems.push(i);
    previous = b.hash;
  });
  return { valid: problems.length === 0, blocks: blocks.length, problems };
}

function sign(privatePem, data) {
  return crypto.sign(null, data, crypto.createPrivateKey(privatePem));
}
function verify(publicPem, data, signature) {
  try { return crypto.verify(null, data, crypto.createPublicKey(publicPem), signature); } catch { return false; }
}

async function addInvisibleWatermark(pdfBytes, token) {
  const pdf = await PDFDocument.load(pdfBytes);
  for (const page of pdf.getPages()) {
    const { width, height } = page.getSize();
    page.drawText(`SENTINEL:${token}`, {
      x: Math.max(0, width - 2), y: Math.max(0, height - 2), size: 0.1,
      color: rgb(1, 1, 1), opacity: 0.01
    });
  }
  pdf.setSubject(`${pdf.getSubject() || ''} | SENTINEL:${token}`);
  return Buffer.from(await pdf.save({ useObjectStreams: true }));
}
function extractToken(buf) {
  const m = buf.toString('latin1').match(/SENTINEL:([A-Za-z0-9_-]{20,64})/);
  return m?.[1] || null;
}

function sampleBootstrap() {
  if (recipients().length) return;
  const samples = [
    ['R-DEMO01', 'Commander A. Rao', 'WESEE / Secure Distribution Cell', 'Authorized Recipient'],
    ['R-DEMO02', 'Lt. K. Iyer', 'Naval Cyber Operations', 'Authorized Recipient']
  ];
  const out = [];
  for (const [id, name, unit, role] of samples) {
    try {
      const keys = generatePQC(id);
      out.push({ id, name, unit, role, createdAt: now(), algorithms: { kem: 'ML-KEM-768 / FIPS 203', signature: 'ML-DSA-65 / FIPS 204' }, publicKeys: keys });
    } catch (e) { console.warn('Sample PQC bootstrap:', e.message); }
  }
  if (out.length) saveRecipients(out);
}
sampleBootstrap();

app.get('/api/health', (req, res) => res.json({ ok: true, app: 'SENTINEL', runtime: 'Vercel Node.js 24', storage: '/tmp ephemeral', pqc: true, ledger: verifyLedger(), time: now() }));
app.get('/api/dashboard', (req, res) => {
  const rs = recipients(), ds = documents(), ls = ledgerBlocks();
  res.json({ stats: { recipients: rs.length, documents: ds.length, decryptions: ls.filter(x => x.payload?.type === 'DECRYPTION').length, ledgerBlocks: ls.length }, ledger: verifyLedger(), security: { kem: 'ML-KEM-768 / FIPS 203', signature: 'ML-DSA-65 / FIPS 204', encryption: 'AES-256-GCM', hash: 'SHA-256', storage: 'ephemeral /tmp — no database', network: 'Vercel-hosted demo' }, recent: ls.slice(-8).reverse() });
});
app.get('/api/recipients', (req, res) => res.json(recipients().map(r => ({ ...r, privateKeysStored: true }))));
app.post('/api/recipients', (req, res) => {
  try {
    const { name, unit, role = 'Authorized Recipient' } = req.body;
    if (!name || !unit) return res.status(400).json({ error: 'name and unit are required' });
    const id = `R-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const keys = generatePQC(id);
    const rec = { id, name, unit, role, createdAt: now(), algorithms: { kem: 'ML-KEM-768 / FIPS 203', signature: 'ML-DSA-65 / FIPS 204' }, publicKeys: keys };
    const all = recipients(); all.push(rec); saveRecipients(all); res.json(rec);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/documents', (req, res) => res.json(documents()));
app.post('/api/documents', upload.single('document'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'PDF required' });
    const original = fs.readFileSync(req.file.path);
    if (original.subarray(0, 5).toString() !== '%PDF-') { fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: 'Only PDF files are accepted' }); }
    const id = `DOC-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
    fs.copyFileSync(req.file.path, f('documents', `${id}.pdf`));
    fs.rmSync(req.file.path, { force: true });
    const d = { id, name: req.file.originalname, size: original.length, sha256: sha256(original), createdAt: now(), type: 'PDF', status: 'PROTECTED' };
    const all = documents(); all.push(d); saveDocuments(all); res.json(d);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/distribute', (req, res) => {
  try {
    const { documentId, recipientId } = req.body;
    const d = documents().find(x => x.id === documentId), r = recipients().find(x => x.id === recipientId);
    if (!d || !r) return res.status(404).json({ error: 'document or recipient not found' });
    const pdf = fs.readFileSync(f('documents', `${d.id}.pdf`));
    const cek = crypto.randomBytes(32);
    const kem = crypto.encapsulate(crypto.createPublicKey(r.publicKeys.kemPublic));
    const wrapIv = crypto.randomBytes(12), contentIv = crypto.randomBytes(12);
    const wrapKey = crypto.hkdfSync('sha256', kem.sharedKey, Buffer.from('SENTINEL-WRAP-V2'), Buffer.from(d.id), 32);
    const w = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapIv); w.setAAD(Buffer.from(`${d.id}|${r.id}`));
    const wrapped = Buffer.concat([w.update(cek), w.final()]);
    const c = crypto.createCipheriv('aes-256-gcm', cek, contentIv); c.setAAD(Buffer.from(`${d.id}|${r.id}`));
    const ciphertext = Buffer.concat([c.update(pdf), c.final()]);
    const env = { version: 2, documentId: d.id, recipientId: r.id, algorithms: { kem: 'ML-KEM-768', content: 'AES-256-GCM' }, kemCiphertext: b64(kem.ciphertext), wrapIv: b64(wrapIv), wrappedContentKey: b64(wrapped), wrapTag: b64(w.getAuthTag()), contentIv: b64(contentIv), contentTag: b64(c.getAuthTag()), ciphertext: b64(ciphertext) };
    const name = `${d.id}--${r.id}.envelope.json`; writeJson(f('documents', name), env);
    res.json({ ok: true, envelope: name, documentId: d.id, recipientId: r.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/decrypt', async (req, res) => {
  try {
    const { documentId, recipientId, envelopeName } = req.body;
    const r = recipients().find(x => x.id === recipientId);
    if (!r) return res.status(404).json({ error: 'recipient not found' });
    const env = readJson(f('documents', envelopeName || `${documentId}--${recipientId}.envelope.json`), null);
    if (!env) return res.status(404).json({ error: 'envelope not found; Vercel runtime state may have expired' });
    const privPem = fs.readFileSync(f('keys', `${recipientId}.kem.private.pem`), 'utf8');
    const shared = crypto.decapsulate(crypto.createPrivateKey(privPem), unb64(env.kemCiphertext));
    const wrapKey = crypto.hkdfSync('sha256', shared, Buffer.from('SENTINEL-WRAP-V2'), Buffer.from(documentId), 32);
    const w = crypto.createDecipheriv('aes-256-gcm', wrapKey, unb64(env.wrapIv)); w.setAAD(Buffer.from(`${documentId}|${recipientId}`)); w.setAuthTag(unb64(env.wrapTag));
    const cek = Buffer.concat([w.update(unb64(env.wrappedContentKey)), w.final()]);
    const c = crypto.createDecipheriv('aes-256-gcm', cek, unb64(env.contentIv)); c.setAAD(Buffer.from(`${documentId}|${recipientId}`)); c.setAuthTag(unb64(env.contentTag));
    const original = Buffer.concat([c.update(unb64(env.ciphertext)), c.final()]);
    const token = crypto.randomBytes(24).toString('base64url');
    const watermarked = await addInvisibleWatermark(original, token);
    const outName = `${documentId}--${recipientId}--${token}.pdf`; fs.writeFileSync(f('temp', outName), watermarked);
    const event = { type: 'DECRYPTION', eventId: `EVT-${crypto.randomBytes(8).toString('hex').toUpperCase()}`, documentId, recipientId, recipientName: r.name, sessionId: `SES-${crypto.randomBytes(8).toString('hex').toUpperCase()}`, watermark: token, documentHash: sha256(original), watermarkedHash: sha256(watermarked), timestamp: now(), algorithms: { kem: 'ML-KEM-768 / FIPS 203', signature: 'ML-DSA-65 / FIPS 204', watermark: 'PDF content-stream fingerprint' }, purpose: 'authorized decryption' };
    const privateSig = fs.readFileSync(f('keys', `${recipientId}.sig.private.pem`), 'utf8');
    const signature = sign(privateSig, Buffer.from(canonical(event)));
    const block = appendLedger({ ...event, signature: b64(signature), signingPublicKey: r.publicKeys.sigPublic });
    res.json({ ok: true, event, ledger: block, download: `/api/download/${encodeURIComponent(outName)}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/download/:name', (req, res) => {
  const name = path.basename(req.params.name), p = f('temp', name);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'File expired from temporary storage' });
  res.download(p, name);
});
app.post('/api/forensics/extract', upload.single('document'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'PDF required' });
    const buf = fs.readFileSync(req.file.path); fs.rmSync(req.file.path, { force: true });
    const watermark = extractToken(buf);
    if (!watermark) return res.json({ found: false, message: 'No SENTINEL fingerprint detected' });
    const match = ledgerBlocks().find(x => x.payload?.type === 'DECRYPTION' && x.payload.watermark === watermark) || null;
    res.json({ found: true, watermark, match, ledgerIntegrity: verifyLedger(), note: match ? 'Fingerprint matched to a signed provenance event.' : 'Fingerprint found but no local ledger match exists.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/ledger', (req, res) => res.json({ integrity: verifyLedger(), blocks: ledgerBlocks().reverse() }));
app.post('/api/ledger/verify-event', (req, res) => {
  const b = ledgerBlocks().find(x => x.payload?.eventId === req.body?.eventId);
  if (!b) return res.status(404).json({ error: 'event not found' });
  const r = recipients().find(x => x.id === b.payload.recipientId);
  if (!r) return res.json({ ledgerValid: verifyLedger().valid, signatureValid: false, block: b });
  const signed = { ...b.payload }; delete signed.signature; delete signed.signingPublicKey;
  const signatureValid = verify(r.publicKeys.sigPublic, Buffer.from(canonical(signed)), unb64(b.payload.signature));
  res.json({ ledgerValid: verifyLedger().valid, signatureValid, block: b, recipient: { id: r.id, name: r.name, unit: r.unit } });
});

export default app;
