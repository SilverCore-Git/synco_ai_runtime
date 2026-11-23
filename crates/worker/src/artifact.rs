//! Outil `send_file` (lot L08e, docs/plan/13) : fichier texte envoyé par l'agent dans la conversation.
//!
//! Ce module est pur (aucune E/S) : description donnée au modèle, validation du nom, de l'extension
//! et du contenu (§2.2), forme réduite des arguments gardés dans le transcript (§2.4), chiffrement de
//! `meta` et du contenu sous `CK` (§3) et corps du dépôt (§5.1). Le dépôt, la trame et la politique
//! vivent dans la boucle d'agent (`agent::send_file`).
//!
//! Aucun contenu, aucun nom n'est journalisé ni mis dans une erreur : les refus sont des codes fixes.

use serde_json::{Value, json};
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{RandomSource, SymmetricKey, encoding, plan, primitives};

use crate::provider::ToolDef;

/// Nom de l'outil (propre au worker, absent du manifeste de l'API).
pub const SEND_FILE: &str = "send_file";
/// Octets UTF-8 au plus du contenu (PC85, 256 Kio).
pub const MAX_CONTENT_BYTES: usize = 262_144;
/// Points de code au plus du nom final, extension comprise.
pub const MAX_NAME_CHARS: usize = 120;
/// Octets au plus du clair de `meta`.
pub const MAX_META_BYTES: usize = 1_024;
/// Artefacts déposés au plus par tour (PC82).
pub const MAX_PER_TURN: usize = 5;
/// Extensions permises (`TEXT_FILE_FORMATS`, PC71).
pub const FORMATS: [&str; 25] = [
    "txt", "md", "log", "csv", "json", "xml", "yml", "ini", "sql", "html", "css", "scss", "js", "ts", "vue", "py",
    "sh", "java", "c", "cpp", "cs", "php", "go", "rs", "rb",
];

/// Description de l'outil donnée au modèle (13 §2.1), reprise telle quelle.
pub const DESCRIPTION: &str = "Envoie un fichier texte dans la conversation, comme une pièce jointe : l'utilisateur pourra l'ouvrir, le télécharger ou l'enregistrer dans un de ses espaces. Utilise-le quand le résultat est un document à garder (code, tableau CSV, note Markdown, configuration…), plutôt que de le recopier dans ta réponse. `ext` est l'une des extensions permises ; `content` est le texte complet, **256 Kio au plus**. Au plus 5 fichiers par réponse et 20 par conversation. Tu ne pourras pas relire le fichier après l'envoi : résume dans ta réponse ce qu'il contient. Pour créer un fichier directement dans un espace, propose plutôt un plan d'action (`file.create_text`).";

/// `send_file` tel que le voit le modèle.
#[must_use]
pub fn tool_def() -> ToolDef {
    ToolDef {
        name: SEND_FILE.to_owned(),
        description: DESCRIPTION.to_owned(),
        parameters: json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Nom affiché du fichier, avec ou sans extension." },
                "ext": { "type": "string", "enum": FORMATS, "description": "Extension du fichier." },
                "content": { "type": "string", "description": "Texte complet du fichier (256 Kio au plus)." }
            },
            "required": ["name", "ext", "content"]
        }),
    }
}

/// Fichier validé.
#[derive(Clone, PartialEq, Eq)]
pub struct File {
    /// Nom final (§2.2 point 3).
    pub name: String,
    /// Extension normalisée (liste du §2.1).
    pub ext: String,
    /// Texte du fichier.
    pub content: String,
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File").field("ext", &self.ext).field("size", &self.content.len()).finish_non_exhaustive()
    }
}

/// Refus de validation : code de résultat d'outil (13 §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `ext` hors liste.
    Format,
    /// Nom vide, interdit ou trop long.
    Name,
    /// Contenu vide ou contenant U+0000.
    NotText,
    /// Contenu de plus de 256 Kio.
    TooLarge,
}

impl Refusal {
    /// Code du §10.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "artifact_format",
            Self::Name => "artifact_name",
            Self::NotText => "artifact_not_text",
            Self::TooLarge => "artifact_too_large",
        }
    }
}

/// Résultat d'outil d'un refus : `{"error":"<code>"}` (avec `max` pour `artifact_too_large`).
#[must_use]
pub fn error_result(code: &str) -> Value {
    if code == "artifact_too_large" {
        json!({ "error": code, "max": MAX_CONTENT_BYTES })
    } else {
        json!({ "error": code })
    }
}

fn forbidden_in_name(c: char) -> bool {
    matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        || matches!(c, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Valide un appel du modèle, dans l'ordre du §2.2 (extension, nom, nom final, contenu). Le contrôle
/// du nombre par tour est fait par l'appelant, qui connaît l'historique.
pub fn validate(args: &Value) -> Result<File, Refusal> {
    let text = |k: &str| args.get(k).and_then(Value::as_str);
    // 1. ext : un `.` initial retiré, minuscules ASCII.
    let ext = text("ext").ok_or(Refusal::Format)?;
    let ext = ext.strip_prefix('.').unwrap_or(ext).to_ascii_lowercase();
    if !FORMATS.contains(&ext.as_str()) {
        return Err(Refusal::Format);
    }
    // 2. name.
    let name = text("name").ok_or(Refusal::Name)?.trim();
    if name.is_empty() || name.chars().any(forbidden_in_name) || name.starts_with('.') || name.ends_with('.') {
        return Err(Refusal::Name);
    }
    // 3. nom final (`buildFileName`).
    let has_ext = name.rsplit_once('.').is_some_and(|(_, last)| last.eq_ignore_ascii_case(&ext));
    let name = if has_ext { name.to_owned() } else { format!("{name}.{ext}") };
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(Refusal::Name);
    }
    // 4. content.
    let content = text("content").ok_or(Refusal::NotText)?;
    if content.is_empty() || content.contains('\0') {
        return Err(Refusal::NotText);
    }
    if content.len() > MAX_CONTENT_BYTES {
        return Err(Refusal::TooLarge);
    }
    Ok(File { name, ext, content: content.to_owned() })
}

/// Forme réduite des arguments d'un appel réussi (§2.4) : jamais le contenu.
#[must_use]
pub fn reduced_args(artifact_id: &str, file: &File) -> Value {
    json!({ "artifactId": artifact_id, "ext": file.ext, "name": file.name })
}

/// Arguments gardés pour un appel refusé ou non envoyé : `name` et `ext` seulement (chaînes courtes),
/// jamais `content` ni un champ inconnu.
#[must_use]
pub fn refused_args(args: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for (k, max) in [("name", 256usize), ("ext", 32)] {
        if let Some(s) = args.get(k).and_then(Value::as_str) {
            out.insert(k.to_owned(), Value::String(s.chars().take(max).collect()));
        }
    }
    Value::Object(out)
}

/// Résultat d'outil d'un envoi réussi (§2.3).
#[must_use]
pub fn success_result(artifact_id: &str, file: &File) -> Value {
    json!({ "artifactId": artifact_id, "name": file.name, "size": file.content.len() })
}

/// Artefact chiffré, prêt au dépôt.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// `gcm1:` de `JCS(meta)`.
    pub meta: String,
    /// `gcm1:` du contenu.
    pub value: String,
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed").finish_non_exhaustive()
    }
}

/// Identifiants qui lient l'artefact à sa conversation, son message et son appel (§3).
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    /// Conversation.
    pub session_id: &'a str,
    /// Message assistant porteur.
    pub message_id: &'a str,
    /// Appel `send_file`.
    pub tool_call_id: &'a str,
    /// Identifiant de l'artefact (UUID v4 tiré par le worker).
    pub artifact_id: &'a str,
}

/// Chiffre `meta` puis le contenu sous `CK` (13 §3) ; l'`artifactId` est en position de `messageId`
/// dans l'AAD. Une valeur de `meta` hors borne ou un identifiant invalide sont refusés.
pub fn seal(
    ck: &SymmetricKey,
    b: &Binding<'_>,
    file: &File,
    rng: &mut impl RandomSource,
) -> synco_e2ee::Result<Sealed> {
    let meta = json!({
        "v": 1, "id": b.artifact_id, "sessionId": b.session_id, "messageId": b.message_id,
        "toolCallId": b.tool_call_id, "name": file.name, "ext": file.ext, "size": file.content.len(),
        "sha256": encoding::hex(&primitives::sha256(file.content.as_bytes())),
    });
    let clear = plan::jcs(&meta)?;
    if clear.len() > MAX_META_BYTES {
        return Err(synco_e2ee::Error::InvalidInput);
    }
    let meta = session::encrypt_field(ck, b.session_id, b.artifact_id, &FieldName::ArtifactMeta, &clear, rng)?;
    let value = session::encrypt_field(ck, b.session_id, b.artifact_id, &FieldName::Artifact, &file.content, rng)?;
    Ok(Sealed { meta, value })
}

/// Corps de `POST …/artifacts` (§5.1).
#[must_use]
pub fn deposit_body(lease_epoch: u64, artifact_id: &str, sealed: &Sealed) -> Value {
    json!({ "leaseEpoch": lease_epoch, "id": artifact_id, "meta": sealed.meta, "value": sealed.value })
}
