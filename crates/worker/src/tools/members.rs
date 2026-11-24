//! Outils `client` du domaine `members` exécutés par le worker (L15d). Vide au socle L15-0 : le domaine y
//! déclare ses noms dans [`HANDLED`] et les exécute dans [`run`], sans toucher à `mod.rs`.

use serde_json::Value;

use super::{Outcome, ToolCtx};

/// Noms des outils `client` de ce domaine que le worker sait exécuter.
pub const HANDLED: [&str; 0] = [];

/// Exécute l'outil `name` s'il appartient à ce domaine, `None` sinon.
pub async fn run(_ctx: &ToolCtx<'_>, _name: &str, _args: &Value) -> Option<Outcome> {
    None
}
