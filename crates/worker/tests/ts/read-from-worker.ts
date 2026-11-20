/**
 * Test croisé Rust → TS (lot L07) : le code **réel** de synco_app relit ce que le worker a écrit.
 *
 *   export PATH=$HOME/.bun/bin:$PATH
 *   bun crates/worker/tests/ts/read-from-worker.ts            (synco_app à côté de synco_ai_runtime)
 *   SYNCO_APP=/chemin/vers/synco_app bun crates/worker/tests/ts/read-from-worker.ts   (sinon, ex. worktree)
 *
 * Lecture seule de synco_app : `decryptAiField` (crypto.ts), `decryptThreadKeyWithRsa` (crypto.ts),
 * `verifyRt1Envelope` (runtimeDelegation.ts) sont importés ; `decryptGatewaySessionMessages` et
 * `convertStoredMessagesToChatMessages` (non exportés d'AIService.ts) sont extraits du source tel
 * quel et transpilés par Bun, sans rien écrire dans synco_app.
 * Fixture : crates/worker/tests/fixtures/transcript-from-worker.json (régénérée par
 * `L07_WRITE_FIXTURES=1 cargo test -p synco-ai-runtime-worker --test agent create_thread`).
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const here = dirname(new URL(import.meta.url).pathname);
const app = resolve(process.env.SYNCO_APP ?? join(here, '../../../../../synco_app'));
const fixture = JSON.parse(readFileSync(join(here, '../fixtures/transcript-from-worker.json'), 'utf8'));

const crypto_ = await import(join(app, 'src/assets/utils/crypto.ts'));
const rd = await import(join(app, 'src/assets/utils/runtimeDelegation.ts'));

let failures = 0;
function check(cond: boolean, what: string): void {
    if (cond) console.log(`ok   ${what}`);
    else {
        failures++;
        console.error(`ÉCHEC ${what}`);
    }
}

/** Extrait une fonction de premier niveau d'AIService.ts (source de l'app, inchangée). */
function extract(source: string, name: string): string {
    const start = source.search(new RegExp(`(async )?function ${name}\\(`));
    if (start < 0) throw new Error(`fonction ${name} introuvable dans AIService.ts`);
    let depth = 0;
    for (let i = source.indexOf('{', source.indexOf(')', start)); i < source.length; i++) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`fin de ${name} introuvable`);
}

const aiService = readFileSync(join(app, 'src/services/AIService.ts'), 'utf8');
const ts = [extract(aiService, 'decryptGatewaySessionMessages'), extract(aiService, 'convertStoredMessagesToChatMessages')].join('\n\n');
const js = new Bun.Transpiler({ loader: 'ts' }).transformSync(ts);
const factory = new Function('decryptAiField', `${js}\nreturn { decryptGatewaySessionMessages, convertStoredMessagesToChatMessages };`);
const { decryptGatewaySessionMessages, convertStoredMessagesToChatMessages } = factory(crypto_.decryptAiField);

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const ck = await crypto.subtle.importKey('raw', hexToBytes(fixture.ckHex), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

// 1. Historique : déchiffré par le chemin de l'app, identique au clair attendu.
const clear = await decryptGatewaySessionMessages(ck, fixture.sessionId, fixture.messages);
check(JSON.stringify(clear.map((m: any) => m.content)) === JSON.stringify(fixture.expectedClear.map((m: any) => m.content)), 'content déchiffré');
const flat = JSON.stringify(clear);
check(!flat.includes('Contenu illisible') && !flat.includes('Résultat illisible'), 'aucun champ illisible (marqueurs de l\'app)');
const calls = clear.flatMap((m: any) => m.toolCalls ?? []);
check(calls.length === 1 && calls[0].name === 'create_thread' && Array.isArray(calls[0].arguments.threads), 'arguments d\'outil déchiffrés (objet JSON)');
const toolMsg = clear.find((m: any) => m.role === 'tool');
check(Array.isArray(toolMsg?.toolResult?.threads) && toolMsg.toolResult.threads.length === 2, 'résultat d\'outil déchiffré');

// 2. Affichage : la timeline d'OrgAI.vue reconstruite depuis l'historique.
const chat = convertStoredMessagesToChatMessages(clear);
check(chat.length === 2 && chat[0].role === 'user' && chat[1].viaAgentLoop === true, 'un tour utilisateur, un tour assistant');
const parts = chat[1].parts;
const tool = parts.find((p: any) => p.type === 'tool')?.tool;
check(tool?.status === 'done' && tool?.name === 'create_thread' && tool?.category === 'client', 'outil affiché « done » (ToolStepItem)');
check(parts.some((p: any) => p.type === 'text' && p.text === 'Salons créés.'), 'texte final affiché');
check(chat[1].usage?.totalTokens === 26, 'usage cumulé du tour');

// 3. Salon créé par le runtime : clé ouverte par le membre, enveloppe rt1 vérifiée.
const t = fixture.thread;
const priv = await crypto.subtle.importKey('jwk', t.memberPrivateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
const threadKey = await crypto_.decryptThreadKeyWithRsa(t.encryptedKey, priv);
const raw = await crypto.subtle.exportKey('raw', threadKey);
check(raw.byteLength === 32, 'clé de salon ouverte (decryptThreadKeyWithRsa)');
let verified = true;
try {
    await rd.verifyRt1Envelope(t.cskPublic, raw, { ctx: t.ctx, version: t.version, commitment: t.commitment, signature: t.signature }, t.delegationId);
} catch (e) {
    verified = false;
    console.error(e);
}
check(verified, 'enveloppe rt1 vérifiée (verifyRt1Envelope)');
let forged = false;
try {
    await rd.verifyRt1Envelope(t.cskPublic, raw, { ctx: t.ctx, version: t.version, commitment: t.commitment, signature: t.signature }, 'autre-delegation');
} catch {
    forged = true;
}
check(forged, 'enveloppe refusée pour une autre délégation');

if (failures > 0) {
    console.error(`${failures} échec(s)`);
    process.exit(1);
}
console.log('test croisé Rust → TS : OK');
