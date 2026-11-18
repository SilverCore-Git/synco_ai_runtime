// Exemples illustratifs de la spécification L00 (docs/plan/), NON normatifs.
//
//   node docs/plan/exemples/exemples.mjs > docs/plan/exemples/exemples.json   (ou bun)
//
// Implémentation indépendante avec node:crypto seul, écrite pour vérifier que chaque format
// de la spec est calculable tel qu'écrit et pour en donner un exemple complet. Ce ne sont PAS
// les vecteurs de référence : ceux-ci sont produits par L01/L02 avec le code réel
// (cf. docs/plan/vectors/README.md). Toutes les clés sont des valeurs de démonstration
// (octets répétés), sans aucune valeur réelle.
//
// Ed25519, HKDF, HMAC et AES-GCM (IV fixés ici) sont déterministes ; les signatures ECDSA ne le
// sont pas : une nouvelle exécution produit d'autres signatures, toutes valides (champs
// « verifies »). exemples.json est la sortie citée par les documents.
import crypto from 'node:crypto';

const b64 = (b) => Buffer.from(b).toString('base64');
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const utf8 = (s) => Buffer.from(s, 'utf8');
const fill = (byte, n = 32) => Buffer.alloc(n, byte);

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function ed25519FromSeed(seed) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv).export({ format: 'jwk' }).x; // b64u
  return { priv, pub };
}
function p256FromScalar(d) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pt = ecdh.getPublicKey(); // 04 || x || y
  const x = b64u(pt.subarray(1, 33)), y = b64u(pt.subarray(33, 65));
  const jwkPriv = { kty: 'EC', crv: 'P-256', d: b64u(d), x, y };
  const priv = crypto.createPrivateKey({ key: jwkPriv, format: 'jwk' });
  return { ecdh, priv, x, y, canon: JSON.stringify({ crv: 'P-256', kty: 'EC', x, y }) };
}
const ecdsa = (priv, bytes) => crypto.sign('sha256', bytes, { key: priv, dsaEncoding: 'ieee-p1363' });
const ecdsaVerify = (canonJwk, bytes, sig) => crypto.verify('sha256', bytes, { key: crypto.createPublicKey({ key: JSON.parse(canonJwk), format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, sig);
const hkdf = (ikm, salt, info) => Buffer.from(crypto.hkdfSync('sha256', ikm, utf8(salt), utf8(info), 32));
function gcmSeal(key, iv, plain, aad) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(utf8(aad));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function base32(bytes) { let bits = 0, v = 0, out = ''; for (const b of bytes) { v = (v << 8) | b; bits += 8; while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(v << (5 - bits)) & 31]; return out; }

const out = {};

// --- Identifiants
const runtimeId = '7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f';
const orgId = 'cm3orgexample0000000000001';
const adminId = '11111111-2222-4333-8444-555555555555';
const userId = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const sessionId = '0f0e0d0c-0b0a-4908-8706-050403020100';
const url = 'https://runtime.example.com';

// --- Clés du runtime
const sig = ed25519FromSeed(fill(0x11));
const kex = p256FromScalar(fill(0x22));
const csk = p256FromScalar(fill(0x33));
const fprInput = `synco-rt-fpr-v1|${runtimeId}|${sig.pub}|${kex.canon}|${csk.canon}`;
const fpr = sha256(utf8(fprInput));
const fprHex = fpr.toString('hex');
const display = fprHex.toUpperCase().match(/.{4}/g).join(' ');
const head = fpr.subarray(0, 16);
const code = (base32(head).slice(0, 26) + base32(sha256(head).subarray(0, 3)).slice(0, 4).slice(0, 2)).match(/.{1,4}/g).join('-');
out.runtimeKeys = { sig: sig.pub, kex: kex.canon, csk: csk.canon, fprInput, fprHex, display, code };

// --- Certificat
const issuedAt = 1795000000;
const admin = p256FromScalar(fill(0x44));
const certBytes = `synco-rt-cert-v1|${orgId}|${runtimeId}|${url}|${sig.pub}|${kex.canon}|${csk.canon}|${adminId}|${issuedAt}|1`;
const certSig = ecdsa(admin.priv, utf8(certBytes));
out.cert = { adminSignKey: admin.canon, certBytes, signature: b64(certSig), verifies: ecdsaVerify(admin.canon, utf8(certBytes), certSig) };

// --- Défi de possession
const clientEph = p256FromScalar(fill(0x66));
const nonce = b64u(fill(0x77));
const transcript = `synco-rt-challenge-v1|delegate|${runtimeId}|${orgId}|${userId}|${nonce}|${clientEph.canon}|${fprHex}`;
const shared = kex.ecdh.computeSecret(clientEph.ecdh.getPublicKey());
const shared2 = clientEph.ecdh.computeSecret(kex.ecdh.getPublicKey());
const kch = hkdf(shared, 'synco-rt-challenge-v1', transcript);
const mac = crypto.createHmac('sha256', kch).update(utf8(transcript)).digest();
const chSig = ecdsa(csk.priv, utf8(transcript));
out.challenge = { transcript, sharedEqual: shared.equals(shared2), mac: b64u(mac), sig: b64u(chSig), sigVerifies: ecdsaVerify(csk.canon, utf8(transcript), chSig) };

// --- Tickets
const api = ed25519FromSeed(fill(0x2b));
function ticket(prefix, domain, kid, claims) {
  const payload = b64u(utf8(JSON.stringify(claims)));
  const signed = `${prefix}.${kid}.${payload}`;
  const s = crypto.sign(null, Buffer.concat([Buffer.from(domain, 'latin1'), utf8(signed)]), api.priv);
  return `${signed}.${b64u(s)}`;
}
const now = 1795000300;
const srtClaims = { op: 'connect', sub: userId, org: orgId, rt: runtimeId, conv: sessionId, iat: now - 10, exp: now + 290 };
const sgtClaims = { op: 'llm', sub: userId, org: orgId, gw: 'https://gateway.example.com', iat: now - 10, exp: now + 290 };
out.tickets = {
  apiPub: api.pub,
  srt1: ticket('srt1', 'synco-ai-runtime-ticket\0', 'ai-2026-11', srtClaims), srtClaims,
  sgt1: ticket('sgt1', 'synco-ai-gateway-ticket\0', 'ai-2026-11', sgtClaims), sgtClaims,
};

// --- Délégation
const delegationId = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const scope = 'org';
const iat = 1795000000, exp = iat + 7 * 86400;
const epk = p256FromScalar(fill(0x99));
const dk = fill(0x88);
const ctx = `synco-rt-delegation-v1|${userId}|${orgId}|${runtimeId}|${delegationId}|${scope}|${iat}|${exp}|${kex.canon}|${epk.canon}`;
const kek = hkdf(epk.ecdh.computeSecret(kex.ecdh.getPublicKey()), 'synco-rt-delegation-v1', ctx);
const wrapBlob = gcmSeal(kek, fill(0xaa, 12), dk, ctx);
const wrap = `srd1.${b64u(utf8(epk.canon))}.${b64u(wrapBlob)}`;
const user = p256FromScalar(fill(0x55));
const mandateBytes = `synco-rt-mandate-v1|${userId}|${orgId}|${runtimeId}|${delegationId}|${scope}|${iat}|${exp}|${fprHex}|${b64u(sha256(utf8(wrap)))}`;
const mandateSig = ecdsa(user.priv, utf8(mandateBytes));
const threadId = 'cm3threadexample000000001';
const threadKey = fill(0xbb);
const entryAad = `synco-rt-entry-v1|${delegationId}|${userId}|${orgId}|${runtimeId}|thread|${threadId}|1`;
const entry = `sre1.${b64u(gcmSeal(dk, fill(0xcc, 12), threadKey, entryAad))}`;
out.delegation = { userSignKey: user.canon, epk: epk.canon, ctx, kek: kek.toString('hex'), wrap, mandateBytes, mandateSig: b64(mandateSig), mandateVerifies: ecdsaVerify(user.canon, utf8(mandateBytes), mandateSig), entryAad, entry };

// --- Champ gcm1 (clé de conversation)
const ck = fill(0xdd);
const messageId = '3c2b1a09-8f7e-4d6c-9b5a-493827161504';
const fieldAad = `${sessionId}:${messageId}:content`;
out.gcm1 = { ck: ck.toString('hex'), aad: fieldAad, value: 'gcm1:' + b64(gcmSeal(ck, fill(0xee, 12), utf8('Bonjour depuis le runtime.'), fieldAad)) };
const wsAad = `${sessionId}:${messageId}:ws:text:2:42`;
out.gcm1ws = { aad: wsAad, value: 'gcm1:' + b64(gcmSeal(ck, fill(0xef, 12), utf8('Bonjour'), wsAad)) };

// --- Requête interne signée
const body = utf8(JSON.stringify({ baseRev: 12, status: 'running' }));
const reqTs = 1795000400;
const reqNonce = b64u(fill(0x5a, 16));
const authId = '9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a';
const reqStr = `POST\n/api/runtime/v1/conversations/${sessionId}/status\n${reqTs}\n${reqNonce}\n${runtimeId}\n${authId}\n${b64u(sha256(body))}`;
const reqSig = crypto.sign(null, Buffer.concat([Buffer.from('synco-rt-request-v1\0', 'latin1'), utf8(reqStr)]), sig.priv);
out.request = { body: body.toString(), reqStr, signature: b64u(reqSig) };

// --- Enveloppe FC4 rt1 (clé créée par le runtime)
const kctx = `thread:${threadId}`;
const commitment = b64(sha256(Buffer.concat([utf8(`synco-key-commit-v1|${kctx}|1|`), threadKey])));
const rtEnvBytes = `synco-key-envelope-rt-v1|${kctx}|1|${commitment}|${delegationId}`;
const rtEnvSig = ecdsa(csk.priv, utf8(rtEnvBytes));
out.rt1 = { creatorId: `rt1:${delegationId}`, commitment, bytes: rtEnvBytes, signature: b64(rtEnvSig), verifies: ecdsaVerify(csk.canon, utf8(rtEnvBytes), rtEnvSig) };

console.log(JSON.stringify(out, null, 2));
