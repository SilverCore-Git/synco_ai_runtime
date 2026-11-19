# synco-e2ee

Formats E2EE de Synco en Rust, compatibles octet pour octet avec le client TypeScript
(`synco_app/src/assets/utils/`) :

- formats E2EE v4 existants dont le runtime a besoin : enveloppes FC4 des clés de salon et d'espace
  (commitment, signature), champs `gcm1:` des conversations, chaîne de transitions d'identité ;
  plus, pour les tests de compatibilité, la clé d'identité scellée par AK, l'enveloppe et le
  certificat d'appareil ;
- nouveaux formats de la délégation au Synco AI Runtime (`docs/plan/` de ce dépôt) : empreinte,
  code d'appairage, URL canonique, certificat, défi de possession, enveloppe de tête `srd1`, mandat,
  entrées `sre1`, enveloppe `rt1`.

API pure : ni entrée/sortie, ni `async`, ni état global. L'aléa est injecté (`RandomSource`,
`OsRandom` par défaut). Les secrets (`SymmetricKey`, `DelegationKey`, `EcdhSecret`,
`EcSigningKey`…) s'effacent à la libération et affichent `***` en `Debug`. Chaque refus est une
`Error` typée dont `code()` donne un code machine stable (`delegation_unusable`,
`cert_bad_signature`…), jamais une panique. `unsafe` est interdit.

| Module | Contenu | Spec |
|---|---|---|
| `runtime_cert` | empreinte, code d'appairage, URL canonique, certificat, défi | `docs/plan/01` |
| `delegation` | enveloppe de tête, mandat, entrées | `docs/plan/03` §3-§5 |
| `keys` | commitments et signatures FC4, enveloppes `rt1` | `keyEnvelope.ts`, `docs/plan/03` §10 |
| `session` | champs `gcm1:` (AAD `sessionId:messageId:fieldName`) | `docs/plan/03` §6.3, `05` §4 |
| `identity` | chaîne de transitions ; clés d'identité scellées (compatibilité) | `e2eeV4.ts` |
| `device` | enveloppe d'AK et certificat d'appareil (compatibilité) | `e2eeV4.ts` |
| `account` | clé de compte AK (compatibilité) | `e2eeV4.ts` |

La crate n'a **aucune** fonction pour transmettre AK ou une clé d'identité à un runtime. Le
scellement d'AK vers un appareil (format v4 existant) n'existe que derrière la fonctionnalité
`legacy-seal`, réservée aux vecteurs : un runtime ne l'active jamais.

## Importer la crate dans un autre projet

Licence : tous droits réservés (`LICENSE` à la racine du dépôt) ; réutilisable par les projets de
Silvercore uniquement. Dépendance git, épinglée sur un commit :

```toml
[dependencies]
synco-e2ee = { git = "https://github.com/SilverCore-Git/synco_ai_runtime.git", rev = "<commit>" }
```

Exemple minimal : le runtime vérifie le mandat, ouvre l'enveloppe de tête puis une entrée.

```rust
use synco_e2ee::delegation::{self, DelegationContext, Scope};
use synco_e2ee::ec::{EcPublicKey, EcdhSecret};

fn ouvrir(
    kex: &EcdhSecret,          // clé privée kex du runtime
    user_sign_key: &EcPublicKey, // clé de signature de l'utilisateur, épinglée (TOFU)
    fpr_hex: &str,             // empreinte du runtime
    wrap: &str,
    mandate_signature: &str,
    entry_ciphertext: &str,
) -> synco_e2ee::Result<synco_e2ee::SymmetricKey> {
    let ctx = DelegationContext {
        user_id: "66666666-7777-4888-9999-aaaaaaaaaaaa".into(),
        org_id: "cm3orgexample0000000000001".into(),
        runtime_id: "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f".into(),
        delegation_id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".into(),
        scope: Scope::Org,
        iat: 1_795_000_000,
        exp: 1_795_604_800,
    };
    ctx.check_time(1_795_000_100, 7 * 86_400)?;
    delegation::verify_mandate(user_sign_key, &ctx, fpr_hex, &delegation::wrap_hash(wrap), mandate_signature)?;
    let dk = delegation::open_delegation(&ctx, kex, wrap)?;
    delegation::open_entry(&dk, &ctx, "thread", "cm3threadexample000000001", 1, entry_ciphertext)
}
```

Chiffrer un champ de conversation :

```rust
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{OsRandom, SymmetricKey};

fn chiffrer(ck: &SymmetricKey) -> synco_e2ee::Result<String> {
    session::encrypt_field(ck, "session-id", "message-id", &FieldName::WsText { epoch: 2, seq: 42 }, "Bonjour", &mut OsRandom)
}
```

## Vecteurs croisés

- **TS → Rust** : `tests/vectors/*.json`, produits par le code réel de l'app
  (`synco_app/scripts/e2ee-vectors/generate.ts`, lancé avec bun) et rejoués par `tests/vectors.rs`.
  Les valeurs déterministes sont comparées à l'octet près ; les signatures ECDSA de WebCrypto ne le
  sont pas (vérification seulement). Régénérer :
  `bun scripts/e2ee-vectors/generate.ts <ce dossier>/tests/vectors` depuis `synco_app`.
- **Rust → TS** : `examples/emit_ts_vectors.rs` écrit `synco_app/scripts/e2ee-vectors/from-rust.json`,
  ouvert par `from-rust.test.ts` (`bun test`).

```sh
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo run -q -p synco-e2ee --example emit_ts_vectors --features legacy-seal > <synco_app>/scripts/e2ee-vectors/from-rust.json
```
