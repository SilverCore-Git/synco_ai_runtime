//! Plan d'action (docs/plan/12-plan-action.md) : fonctions pures partagées par le worker (L08d), le
//! superviseur et, pour la forme et le verrou, l'API (L03g) ; l'appareil a les mêmes en TypeScript
//! (`synco_app/src/assets/utils/aiActionPlan.ts`). Vecteurs : `docs/plan/vectors/action-plan.json`.
//!
//! | Fonction | Spec |
//! |---|---|
//! | [`jcs`] | JSON canonique RFC 8785 restreint aux entiers sûrs (12 §3.3) |
//! | [`plan_aad`], [`phase_result_aad`] | AAD du plan et des résultats de phase (12 §3.3, §9) |
//! | [`encrypt_plan`], [`decrypt_plan`], [`encrypt_phase_result`], [`decrypt_phase_result`] | `gcm1:` sous `CK` |
//! | [`server_digest`], [`plan_server_digests`], [`check_server_call`] | `serverDigests` et verrou `refs` (12 §8.4, PC47) |
//! | [`validate_plan`] | Règles 1 à 6 du §5 et bornes de PC61 |
//! | [`PlanGraph`] | Niveaux, cascade de décision (PC37), dépendantes d'un échec (PC54) |
//! | [`PlanRun`] | Actions prêtes, transitions d'état et statut du plan (12 §7, §8.1, PC58) |
//!
//! Aucune entrée/sortie : l'appelant fournit le manifeste, le délai de l'org et l'aléa.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::delegation::MandateMode;
use crate::encoding::{MAX_SAFE_INTEGER, check_id, hex, is_valid_id};
use crate::error::{Error, Result};
use crate::primitives::sha256;
use crate::rng::RandomSource;
use crate::secret::SymmetricKey;
use crate::session::{self, FieldName};

/// Version du clair (`v`).
pub const PLAN_VERSION: u64 = 1;
/// Nombre maximal d'actions (PC61).
pub const MAX_ACTIONS: usize = 100;
/// Nombre maximal d'entrées d'`after` pour tout le plan (PC61).
pub const MAX_AFTER_ENTRIES: usize = 2_000;
/// Taille maximale de `utf8(JCS(plan))` (256 Kio, PC61).
pub const MAX_PLAN_BYTES: usize = 262_144;
/// Longueur maximale (en octets) d'une valeur `gcm1:` de plan ou de résultat de phase : celle d'un
/// clair de [`MAX_PLAN_BYTES`], soit `5 + 4·⌈(12 + 262 144 + 16) / 3⌉ = 349 569`. Contrôlée **avant**
/// le base64, AES-GCM et le JSON (PC61).
pub const MAX_PLAN_VALUE_LEN: usize = session::VERSION_PREFIX.len() + 4 * (12 + MAX_PLAN_BYTES + 16).div_ceil(3);
/// Durée de vie maximale d'un plan (7 jours, 09 §3).
pub const MAX_PLAN_LIFETIME_SECS: u64 = 604_800;
/// Nombre maximal de groupes (PC58).
pub const MAX_GROUPS: usize = 50;
/// Profondeur maximale d'un JSON canonisé.
const MAX_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// JCS (RFC 8785, entiers seulement)
// ---------------------------------------------------------------------------

/// JSON canonique (12 §3.3) : clés triées par unités UTF-16, aucune espace, chaînes échappées comme
/// `JSON.stringify`, nombres **entiers** de valeur absolue ≤ 2⁵³ − 1 seulement (sinon
/// [`Error::InvalidInput`]).
pub fn jcs(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_jcs(value, &mut out, 0)?;
    Ok(out)
}

fn write_jcs(value: &Value, out: &mut String, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::InvalidInput);
    }
    let next = depth.saturating_add(1);
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let text = if let Some(u) = n.as_u64() {
                (u <= MAX_SAFE_INTEGER).then(|| u.to_string())
            } else {
                n.as_i64().filter(|i| i.unsigned_abs() <= MAX_SAFE_INTEGER).map(|i| i.to_string())
            };
            out.push_str(&text.ok_or(Error::InvalidInput)?);
        }
        Value::String(s) => push_string(s, out)?,
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out, next)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_string(key, out)?;
                out.push(':');
                write_jcs(map.get(key).ok_or(Error::InvalidInput)?, out, next)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Échappement de `serde_json`, identique à celui de `JSON.stringify` pour une chaîne Rust (aucune
/// moitié de paire de substitution possible) : `\"`, `\\`, `\b\f\n\r\t`, `\u00xx` en minuscules.
fn push_string(s: &str, out: &mut String) -> Result<()> {
    out.push_str(&serde_json::to_string(s).map_err(|_| Error::InvalidInput)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// AAD et chiffrement sous CK (12 §3.3, §9)
// ---------------------------------------------------------------------------

/// Exécutant d'une action (12 §4) ; numérote ses phases de 1 en 1 (12 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Executor {
    /// Appareil de l'utilisateur (`plan_result:<k>`).
    Device,
    /// Worker du runtime (`plan_agent_result:<k>`).
    Agent,
}

impl Executor {
    /// Valeur servie par l'API (`device`, `agent`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Agent => "agent",
        }
    }

    /// Lecture stricte.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "device" => Ok(Self::Device),
            "agent" => Ok(Self::Agent),
            _ => Err(Error::InvalidInput),
        }
    }

    /// Nom de champ de l'AAD du résultat de la phase `phase` de cet exécutant.
    #[must_use]
    pub const fn result_field(self, phase: u64) -> FieldName {
        match self {
            Self::Device => FieldName::PlanResult(phase),
            Self::Agent => FieldName::PlanAgentResult(phase),
        }
    }
}

/// `sessionId ":" planId ":plan"`.
pub fn plan_aad(session_id: &str, plan_id: &str) -> Result<String> {
    check_id(session_id)?;
    check_id(plan_id)?;
    Ok(format!("{session_id}:{plan_id}:{}", FieldName::Plan.to_aad_part()?))
}

/// `sessionId ":" planId ":plan_result:" k` (appareil) ou `…:plan_agent_result:" k` (agent), `k ≥ 1`.
pub fn phase_result_aad(session_id: &str, plan_id: &str, executor: Executor, phase: u64) -> Result<String> {
    check_id(session_id)?;
    check_id(plan_id)?;
    Ok(format!("{session_id}:{plan_id}:{}", executor.result_field(phase).to_aad_part()?))
}

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Chiffre le plan : `gcm1:` de `JCS(plan)` sous `CK`, AAD [`plan_aad`] tirée des champs du plan.
/// Un clair de plus de [`MAX_PLAN_BYTES`] est refusé ([`Error::PlanInvalid`]).
pub fn encrypt_plan(ck: &SymmetricKey, plan: &Value, rng: &mut impl RandomSource) -> Result<String> {
    let map = plan.as_object().ok_or(Error::InvalidInput)?;
    let session_id = str_field(map, "sessionId").ok_or(Error::InvalidInput)?;
    let plan_id = str_field(map, "planId").ok_or(Error::InvalidInput)?;
    let clear = jcs(plan)?;
    if clear.len() > MAX_PLAN_BYTES {
        return Err(Error::PlanInvalid);
    }
    session::encrypt_field(ck, session_id, plan_id, &FieldName::Plan, &clear, rng)
}

/// Borne de PC61 sur la valeur chiffrée, avant tout décodage ([`Error::PlanInvalid`]).
const fn check_value_len(value: &str) -> Result<()> {
    if value.len() > MAX_PLAN_VALUE_LEN { Err(Error::PlanInvalid) } else { Ok(()) }
}

/// Lecture stricte d'un clair de plan ou de résultat de phase : JSON de `serde_json` (demi-paire de
/// substitution `"\ud800"` refusée, BOM initial refusé), puis nombres **entiers** sûrs seulement, écrits sans fraction ni exposant
/// (`1.0`, `1e2` et `-0` sont des flottants pour `serde_json`), profondeur ≤ 64, comme [`jcs`]. Tout
/// écart est [`Error::FieldInvalidJson`], comme le parseur strict de l'app (`parseJsonStrict`).
fn parse_clear(clear: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(clear).map_err(|_| Error::FieldInvalidJson)?;
    jcs(&value).map_err(|_| Error::FieldInvalidJson)?;
    Ok(value)
}

/// Déchiffre `pendingToolCall.args` d'un `propose_actions` (stricte) et vérifie que le clair porte
/// ce `sessionId` et ce `planId` ([`Error::PlanInvalid`] sinon). Identifiants non conformes :
/// [`Error::InvalidInput`], avant l'AAD. La validation (§5) reste à faire.
pub fn decrypt_plan(ck: &SymmetricKey, session_id: &str, plan_id: &str, value: &str) -> Result<Value> {
    check_id(session_id)?;
    check_id(plan_id)?;
    check_value_len(value)?;
    let aad_field = FieldName::Plan.to_aad_part()?;
    let clear = session::decrypt_field(ck, session_id, plan_id, &aad_field, value)?;
    let plan = parse_clear(&clear)?;
    let map = plan.as_object().ok_or(Error::PlanInvalid)?;
    if str_field(map, "sessionId") != Some(session_id) || str_field(map, "planId") != Some(plan_id) {
        return Err(Error::PlanInvalid);
    }
    Ok(plan)
}

/// États d'une action (12 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionState {
    /// Acceptée, pas encore démarrée.
    Pending,
    /// En cours.
    Executing,
    /// Terminée avec succès.
    Done,
    /// Terminée en échec.
    Failed,
    /// Ignorée (décochée, dépendante d'une action qui n'a pas abouti, plan arrêté ou expiré).
    Skipped,
    /// Issue inconnue (claim expiré, appel d'agent interrompu).
    UnknownOutcome,
}

impl ActionState {
    /// Valeur des vecteurs et de l'API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Executing => "executing",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::UnknownOutcome => "unknown_outcome",
        }
    }

    /// Lecture stricte.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "executing" => Ok(Self::Executing),
            "done" => Ok(Self::Done),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            "unknown_outcome" => Ok(Self::UnknownOutcome),
            _ => Err(Error::InvalidInput),
        }
    }

    /// État final (l'action ne bougera plus).
    #[must_use]
    pub const fn is_final(self) -> bool {
        !matches!(self, Self::Pending | Self::Executing)
    }
}

/// Clair d'un résultat de phase : `{ v: 1, planId, phase, outcomes: [{ n, state, output? }] }`
/// (12 §9), `outcomes` dans l'ordre strict de `n`, chaque `n` action du plan (`graph`) confiée à
/// l'exécutant de l'AAD (`executor`), état final (ni `pending` ni `executing`), `output` = objet
/// d'identifiants.
fn check_phase_result(value: &Value, plan_id: &str, phase: u64, executor: Executor, graph: &PlanGraph) -> Result<()> {
    let fail = Error::PlanInvalid;
    let map = value.as_object().ok_or(fail)?;
    if map.keys().any(|k| !matches!(k.as_str(), "v" | "planId" | "phase" | "outcomes"))
        || map.get("v").and_then(Value::as_u64) != Some(PLAN_VERSION)
        || str_field(map, "planId") != Some(plan_id)
        || map.get("phase").and_then(Value::as_u64) != Some(phase)
    {
        return Err(fail);
    }
    let mut last = 0u64;
    for outcome in map.get("outcomes").and_then(Value::as_array).ok_or(fail)? {
        let o = outcome.as_object().ok_or(fail)?;
        if o.keys().any(|k| !matches!(k.as_str(), "n" | "state" | "output")) {
            return Err(fail);
        }
        let n = o.get("n").and_then(Value::as_u64).ok_or(fail)?;
        let state = ActionState::parse(str_field(o, "state").ok_or(fail)?).map_err(|_| fail)?;
        let action = index(n).and_then(|i| graph.actions.get(i)).ok_or(fail)?;
        if n <= last || action.executor != executor || !state.is_final() {
            return Err(fail);
        }
        last = n;
        if let Some(output) = o.get("output") {
            let output = output.as_object().ok_or(fail)?;
            if output.iter().any(|(k, v)| !is_export_field(k) || !v.as_str().is_some_and(is_valid_id)) {
                return Err(fail);
            }
        }
    }
    Ok(())
}

/// Chiffre un résultat de phase (`planId` et `phase` lus dans le clair, contrôlés comme à la
/// lecture, contre le graphe du plan).
pub fn encrypt_phase_result(
    ck: &SymmetricKey,
    session_id: &str,
    executor: Executor,
    graph: &PlanGraph,
    result: &Value,
    rng: &mut impl RandomSource,
) -> Result<String> {
    let map = result.as_object().ok_or(Error::InvalidInput)?;
    let plan_id = str_field(map, "planId").ok_or(Error::InvalidInput)?;
    let phase = map.get("phase").and_then(Value::as_u64).ok_or(Error::InvalidInput)?;
    check_phase_result(result, plan_id, phase, executor, graph)?;
    session::encrypt_field(ck, session_id, plan_id, &executor.result_field(phase), &jcs(result)?, rng)
}

/// Déchiffre et recontrôle (12 §8.3 étape 1) un résultat de phase : AAD de cet exécutant et de cette
/// phase, puis `planId`, `phase`, forme du clair et, contre `graph` (le plan déchiffré et validé),
/// appartenance de chaque `n` au plan et à cet exécutant et état final ([`Error::PlanInvalid`]).
pub fn decrypt_phase_result(
    ck: &SymmetricKey,
    session_id: &str,
    plan_id: &str,
    executor: Executor,
    phase: u64,
    graph: &PlanGraph,
    value: &str,
) -> Result<Value> {
    check_id(session_id)?;
    check_id(plan_id)?;
    let field = executor.result_field(phase).to_aad_part()?;
    check_value_len(value)?;
    let clear = session::decrypt_field(ck, session_id, plan_id, &field, value)?;
    let result = parse_clear(&clear)?;
    check_phase_result(&result, plan_id, phase, executor, graph)?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// serverDigests et verrou `refs` (12 §8.4, PC47)
// ---------------------------------------------------------------------------

/// `hex(SHA-256(JCS({ tool, args, argsRefs })))`, `argsRefs` omis s'il est absent.
pub fn server_digest(tool: &str, args: &Map<String, Value>, args_refs: Option<&Map<String, Value>>) -> Result<String> {
    let mut input = Map::new();
    input.insert("tool".to_owned(), Value::String(tool.to_owned()));
    input.insert("args".to_owned(), Value::Object(args.clone()));
    if let Some(refs) = args_refs {
        input.insert("argsRefs".to_owned(), Value::Object(refs.clone()));
    }
    Ok(hex(&sha256(jcs(&Value::Object(input))?.as_bytes())))
}

/// `serverDigests` d'un plan : `(n, condensat)` de chaque action `server.call`, dans l'ordre de `n`.
pub fn plan_server_digests(plan: &Value) -> Result<Vec<(u64, String)>> {
    let actions = plan.get("actions").and_then(Value::as_array).ok_or(Error::InvalidInput)?;
    let mut out = Vec::new();
    for action in actions {
        let a = action.as_object().ok_or(Error::InvalidInput)?;
        if str_field(a, "kind") != Some("server.call") {
            continue;
        }
        let n = a.get("n").and_then(Value::as_u64).ok_or(Error::InvalidInput)?;
        let tool = str_field(a, "tool").ok_or(Error::InvalidInput)?;
        let args = a.get("args").and_then(Value::as_object).ok_or(Error::InvalidInput)?;
        let refs = match a.get("argsRefs") {
            None => None,
            Some(r) => Some(r.as_object().ok_or(Error::InvalidInput)?),
        };
        out.push((n, server_digest(tool, args, refs)?));
    }
    Ok(out)
}

/// Appel d'exécution reçu du runtime pour une action `server.call` (12 §8.4).
#[derive(Debug, Clone, Copy)]
pub struct ServerCall<'a> {
    /// Outil appelé (`:name` de la route).
    pub tool: &'a str,
    /// `args` **non résolus**.
    pub args: &'a Map<String, Value>,
    /// `argsRefs` tels que dans le plan.
    pub args_refs: Option<&'a Map<String, Value>>,
    /// Valeurs résolues par le worker.
    pub refs: Option<&'a Map<String, Value>>,
}

/// Référence `"$<m>.<champ>"` (12 §3.2) : `m ≥ 1` sans zéro de tête, champ exporté connu.
#[must_use]
pub fn parse_arg_ref(text: &str) -> Option<(u64, &str)> {
    let (m, field) = text.strip_prefix('$')?.split_once('.')?;
    let well_formed = !m.is_empty() && m.len() <= 3 && m.bytes().all(|b| b.is_ascii_digit()) && !m.starts_with('0');
    if !well_formed || !is_export_field(field) {
        return None;
    }
    Some((m.parse().ok()?, field))
}

/// Champs qu'une action peut exporter, tous `kind` confondus (12 §4).
fn is_export_field(field: &str) -> bool {
    matches!(field, "id" | "spaceId")
}

/// Verrou de l'API pour un `server.call` (12 §8.4, point 4) : condensat de l'appel reçu égal à
/// `serverDigests[n]`, `refs` avec exactement les clés d'`argsRefs`, chaque valeur égale à la sortie
/// **enregistrée** de l'action visée (`recorded[m]`, absente tant qu'`m` n'est pas `done`). Rend les
/// arguments exécutés `args ∪ refs` ; tout écart est [`Error::ActionNotAccepted`].
pub fn check_server_call(
    expected_digest: &str,
    call: &ServerCall<'_>,
    recorded: &BTreeMap<u64, Map<String, Value>>,
) -> Result<Map<String, Value>> {
    let fail = Error::ActionNotAccepted;
    let digest = server_digest(call.tool, call.args, call.args_refs).map_err(|_| fail)?;
    if !crate::secret::subtle_ct::ct_eq(digest.as_bytes(), expected_digest.as_bytes()) {
        return Err(fail);
    }
    let empty = Map::new();
    let args_refs = call.args_refs.unwrap_or(&empty);
    let refs = call.refs.unwrap_or(&empty);
    if refs.len() != args_refs.len() {
        return Err(fail);
    }
    let mut effective = call.args.clone();
    for (field, target) in args_refs {
        let (m, export) = target.as_str().and_then(parse_arg_ref).ok_or(fail)?;
        let given = refs.get(field).and_then(Value::as_str).ok_or(fail)?;
        let known = recorded.get(&m).and_then(|o| str_field(o, export)).ok_or(fail)?;
        if given != known || effective.contains_key(field) {
            return Err(fail);
        }
        effective.insert(field.clone(), Value::String(given.to_owned()));
    }
    Ok(effective)
}

// ---------------------------------------------------------------------------
// Validation (12 §5, PC61)
// ---------------------------------------------------------------------------

/// Motif d'un plan invalide, rendu au modèle dans `detail` (texte court, sans valeur reçue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanInvalid {
    /// Bornes de PC61 (actions, dépendances, taille) : le modèle doit découper.
    TooLarge,
    /// En-tête (§3.2 : champs, `v`, identifiants, `sessionId`, dates).
    Header,
    /// `groups` / `group`.
    Groups,
    /// Liste d'actions vide ou `n` non consécutifs.
    Actions,
    /// `kind` hors liste ou `tool` mal placé, absent du manifeste ou non `server`/`mutating`.
    Kind,
    /// `args` hors schéma.
    Args,
    /// `after` non conforme.
    After,
    /// `argsRefs` non conforme.
    ArgsRefs,
    /// Exécutant ou `after` servis différents du plan (règle 8, appareil).
    Served,
}

impl PlanInvalid {
    /// `detail` rendu au modèle (`{"error":"plan_invalid","detail":…}`).
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::TooLarge => "plan_too_large",
            Self::Header => "plan_header",
            Self::Groups => "plan_groups",
            Self::Actions => "plan_actions",
            Self::Kind => "plan_kind",
            Self::Args => "plan_args",
            Self::After => "plan_after",
            Self::ArgsRefs => "plan_args_refs",
            Self::Served => "plan_served_mismatch",
        }
    }
}

impl From<PlanInvalid> for Error {
    fn from(_: PlanInvalid) -> Self {
        Self::PlanInvalid
    }
}

/// Type d'un paramètre d'outil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// Chaîne (bornes en caractères).
    String,
    /// Entier sûr (bornes en valeur).
    Integer,
    /// Booléen.
    Boolean,
}

/// Contrainte d'un champ d'`args`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSpec {
    /// Type.
    pub kind: ParamType,
    /// Requis (dans `args` ou fourni par `argsRefs`).
    pub required: bool,
    /// Minimum (longueur ou valeur).
    pub min: Option<u64>,
    /// Maximum (longueur ou valeur).
    pub max: Option<u64>,
    /// Identifiant 00 §3.2 (`spaceId`, `categoryId`…).
    pub id: bool,
    /// Valeurs permises (chaîne).
    pub one_of: Option<&'static [&'static str]>,
}

impl ParamSpec {
    const fn text(required: bool, min: u64, max: u64) -> Self {
        Self { kind: ParamType::String, required, min: Some(min), max: Some(max), id: false, one_of: None }
    }
    const fn id(required: bool) -> Self {
        Self { kind: ParamType::String, required, min: None, max: None, id: true, one_of: None }
    }
    const fn free_text() -> Self {
        Self { kind: ParamType::String, required: false, min: None, max: None, id: false, one_of: None }
    }
}

/// Schéma strict d'`args` : champs connus seulement.
pub type ArgsSchema = BTreeMap<String, ParamSpec>;

/// Outil `server.call` admissible : catégorie `server` et `mutating` (12 §5, règle 4).
#[derive(Debug, Clone, Default)]
pub struct ToolManifest {
    tools: BTreeMap<String, ArgsSchema>,
}

impl ToolManifest {
    /// Lit `GET …/tools` (`{ tools: [...] }` ou la liste) ; ne garde que les outils `server` et
    /// `mutating`. `parameters` en JSON Schema (`properties`, `required`, `type`, `minLength`,
    /// `maxLength`, `minimum`, `maximum`, `enum` ignoré) ou sous la forme abrégée des vecteurs
    /// (`{ champ: { type, required, min, max } }`). Un type non pris en charge rend l'outil
    /// inadmissible en `server.call`.
    #[must_use]
    pub fn from_json(value: &Value) -> Self {
        let list = value.get("tools").unwrap_or(value).as_array().map(Vec::as_slice).unwrap_or_default();
        let mut tools = BTreeMap::new();
        for tool in list {
            let admissible = tool.get("category").and_then(Value::as_str) == Some("server")
                && tool.get("mutating").and_then(Value::as_bool) == Some(true);
            let (Some(name), true) = (tool.get("name").and_then(Value::as_str), admissible) else { continue };
            if let Some(schema) = tool.get("parameters").map_or(Some(ArgsSchema::new()), parse_parameters) {
                tools.insert(name.to_owned(), schema);
            }
        }
        Self { tools }
    }

    /// Schéma d'un outil admissible.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ArgsSchema> {
        self.tools.get(name)
    }
}

fn parse_parameters(params: &Value) -> Option<ArgsSchema> {
    let map = params.as_object()?;
    let mut schema = ArgsSchema::new();
    if let Some(props) = map.get("properties") {
        let required: BTreeSet<&str> =
            map.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
        for (field, spec) in props.as_object()? {
            let s = spec.as_object()?;
            let kind = param_type(str_field(s, "type")?)?;
            let (min, max) = match kind {
                ParamType::String => (s.get("minLength"), s.get("maxLength")),
                _ => (s.get("minimum"), s.get("maximum")),
            };
            let (min, max) = (bound(min)?, bound(max)?);
            let required = required.contains(field.as_str());
            schema.insert(field.clone(), ParamSpec { kind, required, min, max, id: false, one_of: None });
        }
        return Some(schema);
    }
    if map.get("type").and_then(Value::as_str) == Some("object") {
        return (map.len() == 1).then_some(schema);
    }
    for (field, spec) in map {
        let s = spec.as_object()?;
        let kind = param_type(str_field(s, "type")?)?;
        let required = s.get("required").and_then(Value::as_bool).unwrap_or(false);
        let (min, max) = (bound(s.get("min"))?, bound(s.get("max"))?);
        schema.insert(field.clone(), ParamSpec { kind, required, min, max, id: false, one_of: None });
    }
    Some(schema)
}

fn param_type(name: &str) -> Option<ParamType> {
    match name {
        "string" => Some(ParamType::String),
        "integer" => Some(ParamType::Integer),
        "boolean" => Some(ParamType::Boolean),
        _ => None,
    }
}

/// Borne facultative : absente → `Some(None)` ; présente mais non entière → `None` (refus).
fn bound(value: Option<&Value>) -> Option<Option<u64>> {
    match value {
        None => Some(None),
        Some(v) => v.as_u64().map(Some),
    }
}

/// Types d'action v1 (12 §4, liste fermée).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// `category.create`.
    CategoryCreate,
    /// `thread.create`.
    ThreadCreate,
    /// `folder.create`.
    FolderCreate,
    /// `file.create_text`.
    FileCreateText,
    /// `server.call`.
    ServerCall,
}

/// Extensions de `textFileFormats.ts` (`TEXT_FILE_FORMATS`, synco_app) admises par
/// `file.create_text`.
pub const TEXT_FILE_EXTENSIONS: [&str; 25] = [
    "txt", "md", "log", "csv", "json", "xml", "yml", "ini", "sql", "html", "css", "scss", "js", "ts", "vue", "py",
    "sh", "java", "c", "cpp", "cs", "php", "go", "rs", "rb",
];

impl ActionKind {
    /// Lecture stricte.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "category.create" => Ok(Self::CategoryCreate),
            "thread.create" => Ok(Self::ThreadCreate),
            "folder.create" => Ok(Self::FolderCreate),
            "file.create_text" => Ok(Self::FileCreateText),
            "server.call" => Ok(Self::ServerCall),
            _ => Err(Error::InvalidInput),
        }
    }

    /// Champs exportés (12 §4).
    #[must_use]
    pub const fn exports(self) -> &'static [&'static str] {
        match self {
            Self::ServerCall => &["id"],
            _ => &["id", "spaceId"],
        }
    }

    /// Exécutant (12 §4) selon le mode du mandat vérifié et la politique effective de
    /// `create_thread` ; `None` : action hors plan (`thread.create` en mode autonome sous `auto`).
    #[must_use]
    pub const fn executor(self, mode: MandateMode, create_thread_ask: bool) -> Option<Executor> {
        match (self, mode) {
            (Self::ServerCall, _) => Some(Executor::Agent),
            (Self::ThreadCreate, MandateMode::Auto) => {
                if create_thread_ask {
                    Some(Executor::Agent)
                } else {
                    None
                }
            }
            _ => Some(Executor::Device),
        }
    }

    fn schema(self) -> ArgsSchema {
        const TYPES: &[&str] = &["text", "voice"];
        let name = ParamSpec::text(true, 1, 255);
        let fields: Vec<(&str, ParamSpec)> = match self {
            Self::CategoryCreate => vec![("name", name), ("spaceId", ParamSpec::id(false))],
            Self::ThreadCreate => vec![
                ("name", name),
                ("type", ParamSpec { one_of: Some(TYPES), ..ParamSpec::free_text() }.required()),
                ("spaceId", ParamSpec::id(false)),
                ("categoryId", ParamSpec::id(false)),
            ],
            Self::FolderCreate => {
                vec![("spaceId", ParamSpec::id(true)), ("name", name), ("parentFolderId", ParamSpec::id(false))]
            }
            Self::FileCreateText => vec![
                ("spaceId", ParamSpec::id(true)),
                ("name", name),
                ("content", ParamSpec::free_text()),
                ("folderId", ParamSpec::id(false)),
            ],
            Self::ServerCall => vec![],
        };
        fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }
}

impl ParamSpec {
    const fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// Contexte de validation (12 §5).
#[derive(Debug, Clone, Copy)]
pub struct PlanContext<'a> {
    /// La conversation (règle 1).
    pub session_id: &'a str,
    /// `confirmationTimeoutSecs` de l'org (règle 2 ; borné à [`MAX_PLAN_LIFETIME_SECS`]).
    pub max_lifetime_secs: u64,
    /// Manifeste des outils (règle 4).
    pub manifest: &'a ToolManifest,
    /// Mode du mandat vérifié de la délégation courante (exécutants, §4).
    pub mode: MandateMode,
    /// Politique effective de `create_thread` = `ask` (exécutants en mode autonome, §4).
    pub create_thread_ask: bool,
}

/// Action du graphe : ce que l'API connaît sans le contenu (12 §8.1, §12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphAction {
    /// Position (1, 2, 3…).
    pub n: u64,
    /// Exécutant.
    pub executor: Executor,
    /// Dépendances (`needs`), chacune `< n`.
    pub after: Vec<u64>,
}

/// Graphe explicite d'un plan (12 §8.1) : `n` consécutifs depuis 1, `after` distincts et
/// antérieurs (aucun cycle possible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanGraph {
    actions: Vec<GraphAction>,
}

fn index(n: u64) -> Option<usize> {
    usize::try_from(n.checked_sub(1)?).ok()
}

impl PlanGraph {
    /// Construit et contrôle le graphe ([`Error::PlanInvalid`] sinon).
    pub fn new(actions: Vec<GraphAction>) -> Result<Self> {
        if actions.is_empty() || actions.len() > MAX_ACTIONS {
            return Err(Error::PlanInvalid);
        }
        let mut total = 0usize;
        for (i, a) in actions.iter().enumerate() {
            if index(a.n) != Some(i) {
                return Err(Error::PlanInvalid);
            }
            let distinct: BTreeSet<u64> = a.after.iter().copied().collect();
            if distinct.len() != a.after.len() || a.after.iter().any(|&m| m == 0 || m >= a.n) {
                return Err(Error::PlanInvalid);
            }
            total = total.saturating_add(a.after.len());
        }
        if total > MAX_AFTER_ENTRIES {
            return Err(Error::PlanInvalid);
        }
        Ok(Self { actions })
    }

    /// Actions dans l'ordre de `n`.
    #[must_use]
    pub fn actions(&self) -> &[GraphAction] {
        &self.actions
    }

    /// `niveau(a) = 1` sans `after`, sinon `1 + max(niveau(m))` (12 §8.1), dans l'ordre de `n`.
    #[must_use]
    pub fn levels(&self) -> Vec<u64> {
        let mut levels: Vec<u64> = Vec::with_capacity(self.actions.len());
        for a in &self.actions {
            let deepest = a.after.iter().filter_map(|&m| index(m).and_then(|i| levels.get(i))).max().copied();
            levels.push(deepest.unwrap_or(0).saturating_add(1));
        }
        levels
    }

    /// `roots` et toutes leurs dépendantes transitives (par `after`), quel que soit l'exécutant.
    #[must_use]
    pub fn with_dependents(&self, roots: &BTreeSet<u64>) -> BTreeSet<u64> {
        let mut out = roots.clone();
        // `after` ne vise que des actions antérieures : une passe dans l'ordre de `n` suffit.
        for a in &self.actions {
            if a.after.iter().any(|m| out.contains(m)) {
                out.insert(a.n);
            }
        }
        out
    }

    /// Cascade de décision (PC37, 12 §6) : actions décochées et leurs dépendantes, à passer `skipped`.
    pub fn cascade(&self, unchecked: &[u64]) -> Result<BTreeSet<u64>> {
        let roots: BTreeSet<u64> = unchecked.iter().copied().collect();
        if roots.iter().any(|&n| index(n).is_none_or(|i| i >= self.actions.len())) {
            return Err(Error::InvalidInput);
        }
        Ok(self.with_dependents(&roots))
    }

    /// Règle 8 du §5 (appareil) : exécutant et `after` servis par l'API (`PlanView.actions`) égaux à
    /// ceux du plan déchiffré.
    pub fn check_served(&self, served: &[GraphAction]) -> core::result::Result<(), PlanInvalid> {
        let same = served.len() == self.actions.len()
            && served.iter().zip(&self.actions).all(|(s, a)| {
                s.n == a.n && s.executor == a.executor && {
                    let (mut x, mut y) = (s.after.clone(), a.after.clone());
                    x.sort_unstable();
                    y.sort_unstable();
                    x == y
                }
            });
        if same { Ok(()) } else { Err(PlanInvalid::Served) }
    }
}

fn char_len(s: &str) -> u64 {
    u64::try_from(s.chars().count()).unwrap_or(u64::MAX)
}

fn check_arg(spec: &ParamSpec, value: &Value) -> bool {
    match (spec.kind, value) {
        (ParamType::String, Value::String(s)) => {
            let len = char_len(s);
            spec.min.is_none_or(|m| len >= m)
                && spec.max.is_none_or(|m| len <= m)
                && (!spec.id || is_valid_id(s))
                && spec.one_of.is_none_or(|allowed| allowed.contains(&s.as_str()))
        }
        (ParamType::Integer, Value::Number(n)) => {
            n.as_u64()
                .filter(|&u| u <= MAX_SAFE_INTEGER)
                .is_some_and(|u| spec.min.is_none_or(|m| u >= m) && spec.max.is_none_or(|m| u <= m))
                || n.as_i64().is_some_and(|i| i < 0 && i.unsigned_abs() <= MAX_SAFE_INTEGER && spec.min.is_none())
        }
        (ParamType::Boolean, Value::Bool(_)) => true,
        _ => false,
    }
}

const ROOT_FIELDS: [&str; 9] =
    ["v", "planId", "sessionId", "toolCallId", "createdAt", "expiresAt", "summary", "groups", "actions"];
const ACTION_FIELDS: [&str; 7] = ["n", "kind", "tool", "args", "group", "after", "argsRefs"];

fn is_group_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Validation d'un plan (12 §5, règles 1 à 6 et bornes de PC61), faite par le worker avant d'écrire
/// et refaite par l'appareil avant d'afficher. Rend le graphe (exécutants selon le §4 et le mode du
/// contexte). Les règles 7 (annuaire local) et 8 ([`PlanGraph::check_served`]) restent à l'appareil.
pub fn validate_plan(plan: &Value, ctx: &PlanContext<'_>) -> core::result::Result<PlanGraph, PlanInvalid> {
    use PlanInvalid as P;
    let root = plan.as_object().ok_or(P::Header)?;
    let actions = root.get("actions").and_then(Value::as_array).ok_or(P::Actions)?;

    // Règle 3 (PC61) d'abord : le modèle doit savoir qu'il faut découper. Les comptes d'actions et de
    // dépendances passent avant JCS, qui parcourt tout le plan.
    let after_total = actions
        .iter()
        .filter_map(|a| a.get("after").and_then(Value::as_array))
        .fold(0usize, |acc, list| acc.saturating_add(list.len()));
    if actions.len() > MAX_ACTIONS || after_total > MAX_AFTER_ENTRIES {
        return Err(P::TooLarge);
    }
    let clear = jcs(plan).map_err(|_| P::Header)?;
    if clear.len() > MAX_PLAN_BYTES {
        return Err(P::TooLarge);
    }

    // Règles 1 et 2 : en-tête.
    let id_ok = |key: &str| str_field(root, key).is_some_and(is_valid_id);
    let created = root.get("createdAt").and_then(Value::as_u64).filter(|&t| t <= MAX_SAFE_INTEGER);
    let expires = root.get("expiresAt").and_then(Value::as_u64).filter(|&t| t <= MAX_SAFE_INTEGER);
    let lifetime = ctx.max_lifetime_secs.min(MAX_PLAN_LIFETIME_SECS);
    let header_ok = root.keys().all(|k| ROOT_FIELDS.contains(&k.as_str()))
        && root.get("v").and_then(Value::as_u64) == Some(PLAN_VERSION)
        && id_ok("planId")
        && id_ok("sessionId")
        && id_ok("toolCallId")
        && str_field(root, "sessionId") == Some(ctx.session_id)
        && root.get("summary").is_some_and(Value::is_string)
        && matches!((created, expires), (Some(c), Some(e)) if c < e && e.saturating_sub(c) <= lifetime);
    if !header_ok {
        return Err(P::Header);
    }

    // Groupes (PC58).
    let mut groups = BTreeSet::new();
    if let Some(list) = root.get("groups") {
        let list = list.as_array().ok_or(P::Groups)?;
        if list.is_empty() || list.len() > MAX_GROUPS {
            return Err(P::Groups);
        }
        for g in list {
            let g = g.as_object().ok_or(P::Groups)?;
            let id = str_field(g, "id").filter(|id| is_group_id(id)).ok_or(P::Groups)?;
            let label_ok = str_field(g, "label").is_some_and(|l| (1..=100).contains(&char_len(l)));
            if g.len() != 2 || !label_ok || !groups.insert(id) {
                return Err(P::Groups);
            }
        }
    }

    if actions.is_empty() {
        return Err(P::Actions);
    }
    let mut kinds: Vec<ActionKind> = Vec::with_capacity(actions.len());
    let mut graph = Vec::with_capacity(actions.len());
    for (i, action) in actions.iter().enumerate() {
        let a = action.as_object().ok_or(P::Actions)?;
        let n = a.get("n").and_then(Value::as_u64).filter(|&n| index(n) == Some(i)).ok_or(P::Actions)?;
        if !a.keys().all(|k| ACTION_FIELDS.contains(&k.as_str())) {
            return Err(P::Actions);
        }
        if a.get("group").is_some_and(|g| !g.as_str().is_some_and(|g| groups.contains(g))) {
            return Err(P::Groups);
        }

        // Règle 4 : kind, tool, args.
        let kind = str_field(a, "kind").and_then(|k| ActionKind::parse(k).ok()).ok_or(P::Kind)?;
        let schema = match (kind, a.get("tool")) {
            (ActionKind::ServerCall, Some(tool)) => {
                tool.as_str().and_then(|t| ctx.manifest.get(t)).cloned().ok_or(P::Kind)?
            }
            (ActionKind::ServerCall, None) | (_, Some(_)) => return Err(P::Kind),
            (_, None) => kind.schema(),
        };
        let args = a.get("args").and_then(Value::as_object).ok_or(P::Args)?;
        for (field, value) in args {
            if !schema.get(field).is_some_and(|spec| check_arg(spec, value)) {
                return Err(P::Args);
            }
        }
        if kind == ActionKind::FileCreateText {
            // Minuscules ASCII seulement, des deux côtés (l'app n'utilise pas `toLowerCase`).
            let ext = str_field(args, "name").and_then(|name| name.rsplit_once('.')).map(|(_, ext)| ext);
            if !ext.is_some_and(|e| TEXT_FILE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str())) {
                return Err(P::Args);
            }
        }

        // Règle 5 : after.
        let after: Vec<u64> = match a.get("after") {
            None => Vec::new(),
            Some(list) => {
                let list = list.as_array().ok_or(P::After)?;
                list.iter()
                    .map(|m| m.as_u64().filter(|&m| m >= 1 && m < n).ok_or(P::After))
                    .collect::<core::result::Result<_, _>>()?
            }
        };
        if after.iter().collect::<BTreeSet<_>>().len() != after.len() {
            return Err(P::After);
        }

        // Règle 5 : argsRefs (règle 6 : aucune contrainte d'exécutant).
        let refs = match a.get("argsRefs") {
            None => None,
            Some(r) => Some(r.as_object().ok_or(P::ArgsRefs)?),
        };
        for (field, target) in refs.into_iter().flatten() {
            let (m, export) = target.as_str().and_then(parse_arg_ref).ok_or(P::ArgsRefs)?;
            let source = index(m).and_then(|j| kinds.get(j)).ok_or(P::ArgsRefs)?;
            if !after.contains(&m)
                || !source.exports().contains(&export)
                || !schema.contains_key(field)
                || args.contains_key(field)
            {
                return Err(P::ArgsRefs);
            }
        }
        let provided = |f: &String| args.contains_key(f) || refs.is_some_and(|r| r.contains_key(f));
        if schema.iter().any(|(f, spec)| spec.required && !provided(f)) {
            return Err(P::Args);
        }

        let executor = kind.executor(ctx.mode, ctx.create_thread_ask).ok_or(P::Kind)?;
        kinds.push(kind);
        graph.push(GraphAction { n, executor, after });
    }
    PlanGraph::new(graph).map_err(|_| P::After)
}

// ---------------------------------------------------------------------------
// Exécution : actions prêtes, échecs, statut (12 §7, §8.1, PC54, PC58)
// ---------------------------------------------------------------------------

/// Statut d'un plan accepté (12 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStatus {
    /// Accepté, aucune action démarrée.
    Accepted,
    /// Au moins une action démarrée, travail restant.
    Executing,
    /// Fin normale, aucun échec ni issue inconnue.
    Done,
    /// Fin normale avec au moins une action en échec.
    Failed,
    /// Fin normale sans échec, avec au moins une issue inconnue.
    Interrupted,
    /// Arrêté par l'utilisateur (PC55), plus rien en cours.
    Stopped,
    /// Expiré, plus rien en cours.
    Expired,
}

impl PlanStatus {
    /// Valeur de l'API et des vecteurs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Executing => "executing",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Stopped => "stopped",
            Self::Expired => "expired",
        }
    }
}

/// Exécution d'un plan accepté : états des actions et règles de 12 §7–§8.1.
#[derive(Debug, Clone)]
pub struct PlanRun {
    graph: PlanGraph,
    states: Vec<ActionState>,
    started: bool,
    closed: Option<PlanStatus>,
}

impl PlanRun {
    /// Décision `accept` : les actions hors de `accepted` et leurs dépendantes passent `skipped`
    /// (PC37), les autres `pending`.
    pub fn new(graph: PlanGraph, accepted: &[u64]) -> Result<Self> {
        let len = graph.actions.len();
        if accepted.iter().any(|&n| index(n).is_none_or(|i| i >= len)) {
            return Err(Error::InvalidInput);
        }
        let unchecked: Vec<u64> = graph.actions.iter().map(|a| a.n).filter(|n| !accepted.contains(n)).collect();
        let skipped = graph.cascade(&unchecked)?;
        let states = graph
            .actions
            .iter()
            .map(|a| if skipped.contains(&a.n) { ActionState::Skipped } else { ActionState::Pending })
            .collect();
        Ok(Self { graph, states, started: false, closed: None })
    }

    /// Graphe.
    #[must_use]
    pub const fn graph(&self) -> &PlanGraph {
        &self.graph
    }

    /// État de l'action `n`.
    #[must_use]
    pub fn state(&self, n: u64) -> Option<ActionState> {
        index(n).and_then(|i| self.states.get(i)).copied()
    }

    /// Actions prêtes de cet exécutant, plus petite `n` d'abord : `pending` et tout `after` `done`.
    /// Aucune après l'arrêt ou l'expiration.
    #[must_use]
    pub fn ready(&self, executor: Executor) -> Vec<u64> {
        if self.closed.is_some() {
            return Vec::new();
        }
        self.graph
            .actions
            .iter()
            .zip(&self.states)
            .filter(|(a, s)| {
                a.executor == executor
                    && **s == ActionState::Pending
                    && a.after.iter().all(|&m| self.state(m) == Some(ActionState::Done))
            })
            .map(|(a, _)| a.n)
            .collect()
    }

    /// Nombre d'actions de cet exécutant en cours.
    #[must_use]
    pub fn executing(&self, executor: Executor) -> usize {
        self.graph
            .actions
            .iter()
            .zip(&self.states)
            .filter(|(a, s)| a.executor == executor && **s == ActionState::Executing)
            .count()
    }

    /// `pending` → `executing`, seulement pour une action prête (sinon [`Error::InvalidInput`] :
    /// `409 plan_phase_mismatch` ou `action_state_conflict` côté API).
    pub fn start(&mut self, n: u64) -> Result<()> {
        let executor =
            index(n).and_then(|i| self.graph.actions.get(i)).map(|a| a.executor).ok_or(Error::InvalidInput)?;
        if !self.ready(executor).contains(&n) {
            return Err(Error::InvalidInput);
        }
        self.set(n, ActionState::Executing)?;
        self.started = true;
        Ok(())
    }

    /// `executing` → `done`, `failed` ou `unknown_outcome` ; un échec ou une issue inconnue fait passer
    /// `skipped` ses seules dépendantes transitives encore `pending` (PC54).
    pub fn finish(&mut self, n: u64, outcome: ActionState) -> Result<()> {
        if self.state(n) != Some(ActionState::Executing)
            || !matches!(outcome, ActionState::Done | ActionState::Failed | ActionState::UnknownOutcome)
        {
            return Err(Error::InvalidInput);
        }
        self.set(n, outcome)?;
        if outcome != ActionState::Done {
            let roots = BTreeSet::from([n]);
            for m in self.graph.with_dependents(&roots) {
                if self.state(m) == Some(ActionState::Pending) {
                    self.set(m, ActionState::Skipped)?;
                }
            }
        }
        Ok(())
    }

    fn close(&mut self, status: PlanStatus) {
        if self.closed.is_none() {
            self.closed = Some(status);
            for s in &mut self.states {
                if *s == ActionState::Pending {
                    *s = ActionState::Skipped;
                }
            }
        }
    }

    /// `expiresAt` atteint : plus aucune action ne démarre, les `pending` passent `skipped`.
    pub fn expire(&mut self) {
        self.close(PlanStatus::Expired);
    }

    /// « Arrêter le plan » (PC55) : idem, statut `stopped`.
    pub fn stop(&mut self) {
        self.close(PlanStatus::Stopped);
    }

    fn set(&mut self, n: u64, state: ActionState) -> Result<()> {
        *index(n).and_then(|i| self.states.get_mut(i)).ok_or(Error::InvalidInput)? = state;
        Ok(())
    }

    /// Statut (12 §7.1) : tant qu'une action est `pending` ou `executing`, `accepted` ou `executing` ;
    /// ensuite `stopped` / `expired` si le plan a été clos ainsi, sinon `failed`, `interrupted` ou
    /// `done`.
    #[must_use]
    pub fn status(&self) -> PlanStatus {
        if self.states.iter().any(|s| !s.is_final()) {
            return if self.started { PlanStatus::Executing } else { PlanStatus::Accepted };
        }
        if let Some(closed) = self.closed {
            return closed;
        }
        if self.states.contains(&ActionState::Failed) {
            PlanStatus::Failed
        } else if self.states.contains(&ActionState::UnknownOutcome) {
            PlanStatus::Interrupted
        } else {
            PlanStatus::Done
        }
    }
}
