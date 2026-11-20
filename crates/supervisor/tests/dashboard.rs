//! Dashboard (L08, docs/plan/11) : authentification, 401 partout sauf la connexion, CSRF, hôte,
//! en-têtes, force brute, filtres et tri de bout en bout (HTTP réel sur la boucle locale).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "tests"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use runtime_protocol::pipe::Metrics;
use serde_json::{Value, json};
use synco_ai_runtime::clock::now_secs;
use synco_ai_runtime::dashboard::auth::{Auth, MAX_FAILURES_PER_IP, set_password};
use synco_ai_runtime::dashboard::history::History;
use synco_ai_runtime::dashboard::routes::{
    DETAIL_ROUTE, DashboardState, OverviewData, OverviewSource, PUBLIC, ROUTES, serve,
};
use synco_ai_runtime::launcher::{BoxFuture, WorkerExit};
use synco_ai_runtime::seal::KdfParams;

const PW: &str = "mot de passe du dashboard";
const FAST: KdfParams = KdfParams { m_kib: 256, t: 1, p: 1 };

struct Fake;
impl OverviewSource for Fake {
    fn overview(&self) -> BoxFuture<'_, OverviewData> {
        Box::pin(async {
            OverviewData {
                version: "0.0.0".into(),
                runtime_id: "rt".into(),
                fingerprint: "ABCD EF01".into(),
                paired: true,
                ..OverviewData::default()
            }
        })
    }
}

struct Env {
    _dir: tempfile::TempDir,
    addr: SocketAddr,
    client: reqwest::Client,
}

impl Env {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }
    async fn login(&self) -> (String, String) {
        let r = self
            .client
            .post(self.url("/api/login"))
            .header("origin", self.origin())
            .header("content-type", "application/json")
            .body(json!({ "password": PW }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let cookie = r.headers().get("set-cookie").unwrap().to_str().unwrap().to_owned();
        let token = cookie.split(';').next().unwrap().to_owned();
        let csrf = json(r).await["csrf"].as_str().unwrap().to_owned();
        (token, csrf)
    }
    async fn get(&self, path: &str, cookie: &str) -> (u16, Value) {
        let r = self.client.get(self.url(path)).header("cookie", cookie).send().await.unwrap();
        let status = r.status().as_u16();
        (status, json(r).await)
    }
}

async fn json(r: reqwest::Response) -> Value {
    serde_json::from_str(&r.text().await.unwrap()).unwrap_or(Value::Null)
}

fn history() -> Arc<History> {
    let h = History::in_memory(90);
    let t = now_secs();
    let add = |s: &str, user: &str, prov: &str, cost: u64, fail: bool, dt: u64| {
        let id = h.begin_run(s, user, prov, "modele", t - dt);
        h.on_metrics(
            &id,
            &Metrics {
                turn: 1,
                steps: 2,
                prompt_tokens: 100,
                completion_tokens: 10,
                cost_eur_micro: cost,
                ..Metrics::default()
            },
            t - dt + 1,
        );
        if fail {
            h.on_status(&id, "failed", Some("provider_error"), t - dt + 2);
        }
        h.end_run(&id, WorkerExit::Exited(0), false, t - dt + 3);
    };
    add("s-a", "alice", "openai", 3_000, false, 300);
    add("s-b", "bob", "mistral", 9_000, true, 200);
    add("s-c", "alice", "mistral", 1_000, false, 100);
    Arc::new(h)
}

async fn env_with(hops: usize, allowed_hosts: Vec<String>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    set_password(dir.path(), PW, FAST).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state =
        DashboardState::new(history(), Arc::new(Auth::new(dir.path())), Arc::new(Fake), allowed_hosts, hops, addr);
    tokio::spawn(serve(state, listener, std::future::pending()));
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    Env { _dir: dir, addr, client }
}

async fn env() -> Env {
    env_with(0, vec![]).await
}

#[test]
fn la_liste_des_routes_publiques_est_exactement_celle_attendue() {
    assert_eq!(
        PUBLIC,
        [("GET", "/login"), ("GET", "/assets/login.js"), ("GET", "/assets/style.css"), ("POST", "/api/login")]
    );
    for p in PUBLIC {
        assert!(ROUTES.contains(&p));
    }
}

#[tokio::test]
async fn sans_authentification_401_partout_sauf_la_connexion() {
    let e = env().await;
    let mut paths: Vec<String> = ROUTES.iter().map(|(_, p)| (*p).to_owned()).collect();
    paths.extend([
        format!("{DETAIL_ROUTE}s-a"),
        format!("{DETAIL_ROUTE}inconnue"),
        "/api".into(),
        "/api/inconnu".into(),
        "/assets/inconnu.js".into(),
        "/assets/../etc/passwd".into(),
        "/favicon.ico".into(),
        "//".into(),
        "/login/".into(),
    ]);
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let mut checked = 0;
    for path in &paths {
        for m in methods {
            let public = PUBLIC.contains(&(m, path.as_str()));
            let req = e
                .client
                .request(reqwest::Method::from_bytes(m.as_bytes()).unwrap(), e.url(path))
                .header("origin", e.origin())
                .header("content-type", "application/json")
                .body("{}");
            let r = req.send().await.unwrap();
            if public {
                assert_ne!(r.status(), 401, "{m} {path} est public");
            } else {
                assert_eq!(r.status(), 401, "{m} {path} sans session doit répondre 401");
            }
            checked += 1;
        }
    }
    assert!(checked > 100);
    // Cookie invalide ou forgé : 401 aussi.
    for cookie in ["synco_dash=forge", "synco_dash=", "autre=1", "synco_dash=a; synco_dash=b"] {
        assert_eq!(e.get("/api/overview", cookie).await.0, 401, "{cookie}");
    }
}

#[tokio::test]
async fn la_page_de_connexion_est_servie_sans_session() {
    let e = env().await;
    for (p, ct) in [("/login", "text/html"), ("/assets/login.js", "text/javascript"), ("/assets/style.css", "text/css")]
    {
        let r = e.client.get(e.url(p)).send().await.unwrap();
        assert_eq!(r.status(), 200, "{p}");
        assert!(r.headers()["content-type"].to_str().unwrap().starts_with(ct));
    }
}

#[tokio::test]
async fn en_tetes_de_securite_sur_toutes_les_reponses_et_pas_de_script_en_ligne() {
    let e = env().await;
    let (token, _) = e.login().await;
    for (p, cookie) in [
        ("/login", ""),
        ("/api/overview", ""),
        ("/", token.as_str()),
        ("/assets/app.js", token.as_str()),
        ("/inconnu", ""),
    ] {
        let r = e.client.get(e.url(p)).header("cookie", cookie).send().await.unwrap();
        let h = r.headers().clone();
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("script-src 'self'")
                && csp.contains("default-src 'none'")
                && csp.contains("frame-ancestors 'none'")
        );
        assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval") && !csp.contains("http"), "{csp}");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
    }
    // Les pages n'embarquent ni script en ligne, ni style en ligne, ni gestionnaire d'évènement,
    // ni ressource externe ; le JS n'emploie jamais innerHTML.
    for p in ["/login", "/"] {
        let body = e.client.get(e.url(p)).header("cookie", token.as_str()).send().await.unwrap().text().await.unwrap();
        assert!(!body.contains("<script>") && !body.contains(" style=") && !body.contains(" onclick="), "{p}");
        assert!(!body.contains("http://") && !body.contains("https://"), "{p} : ressource externe");
    }
    for p in ["/assets/app.js", "/assets/login.js"] {
        let js = e.client.get(e.url(p)).header("cookie", token.as_str()).send().await.unwrap().text().await.unwrap();
        assert!(!js.contains("innerHTML") && !js.contains("eval(") && !js.contains("document.write"), "{p}");
    }
}

#[tokio::test]
async fn cookie_httponly_samesite_strict_secure_derriere_tls() {
    let e = env().await;
    let r = e
        .client
        .post(e.url("/api/login"))
        .header("origin", e.origin())
        .header("content-type", "application/json")
        .body(json!({ "password": PW }).to_string())
        .send()
        .await
        .unwrap();
    let c = r.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Path=/"), "{c}");
    assert!(!c.contains("Secure"), "pas de Secure en HTTP direct : {c}");
    // Derrière un mandataire TLS de confiance : Secure ; un en-tête forgé n'a aucun effet sans mandataire.
    let proxied = env_with(1, vec![]).await;
    let secure = |env: &Env, proto: &'static str| {
        let req = env
            .client
            .post(env.url("/api/login"))
            .header("origin", env.origin())
            .header("x-forwarded-proto", proto)
            .header("content-type", "application/json")
            .body(json!({ "password": PW }).to_string());
        async move { req.send().await.unwrap().headers()["set-cookie"].to_str().unwrap().contains("Secure") }
    };
    assert!(secure(&proxied, "https").await);
    assert!(!secure(&proxied, "http").await);
    assert!(!secure(&e, "https").await, "sans mandataire de confiance, X-Forwarded-Proto est ignoré");
}

#[tokio::test]
async fn session_ouverte_donne_acces_aux_donnees() {
    let e = env().await;
    let (token, _) = e.login().await;
    let (s, o) = e.get("/api/overview", &token).await;
    assert_eq!(s, 200);
    assert_eq!(o["fingerprint"], "ABCD EF01");
    assert_eq!(o["paired"], true);
    assert!(o["costs"]["day"].as_u64().unwrap() >= 13_000);
    assert_eq!(e.get("/api/sessions/s-a", &token).await.0, 200);
    assert_eq!(e.get("/api/sessions/inconnue", &token).await.0, 404);
    assert_eq!(e.get("/api/sessions/%20%20", &token).await.0, 404);
    assert_eq!(e.get("/chemin-inconnu", &token).await.0, 404);
    assert_eq!(e.get("/", &token).await.0, 200);
}

#[tokio::test]
async fn filtres_et_tri_de_bout_en_bout() {
    let e = env().await;
    let (token, _) = e.login().await;
    let ids = |v: &Value| {
        v["items"].as_array().unwrap().iter().map(|s| s["sessionId"].as_str().unwrap().to_owned()).collect::<Vec<_>>()
    };
    let (_, v) = e.get("/api/sessions?sort=cost&desc=true", &token).await;
    assert_eq!(ids(&v), ["s-b", "s-a", "s-c"]);
    let (_, v) = e.get("/api/sessions?sort=cost&desc=false&limit=2", &token).await;
    assert_eq!((ids(&v), v["total"].as_u64()), (vec!["s-c".to_owned(), "s-a".to_owned()], Some(3)));
    let (_, v) = e.get("/api/sessions?user=alice&provider=mistral", &token).await;
    assert_eq!(ids(&v), ["s-c"]);
    let (_, v) = e.get("/api/sessions?state=failed", &token).await;
    assert_eq!(ids(&v), ["s-b"]);
    let (_, v) = e.get("/api/sessions?errorsOnly=true", &token).await;
    assert_eq!(ids(&v), ["s-b"]);
    let from = now_secs() - 150;
    let (_, v) = e.get(&format!("/api/sessions?from={from}"), &token).await;
    assert_eq!(ids(&v), ["s-c"]);
    assert_eq!(e.get("/api/sessions?sort=n_importe_quoi", &token).await.0, 400);
    assert_eq!(e.get("/api/sessions?limit=abc", &token).await.0, 400);
    let (_, t) = e.get("/api/totals?by=user", &token).await;
    assert_eq!(t[0]["key"], "bob");
    assert_eq!(t[1]["costMicro"], 4_000);
    let (_, t) = e.get("/api/totals?by=provider", &token).await;
    assert_eq!(t[0]["key"], "mistral");
    assert_eq!(e.get("/api/totals?by=autre", &token).await.0, 400);
    assert_eq!(e.get("/api/totals", &token).await.0, 400);
}

#[tokio::test]
async fn csrf_origine_et_deconnexion() {
    let e = env().await;
    let (token, csrf) = e.login().await;
    let logout = |origin: Option<String>, csrf: Option<String>, cookie: String| {
        let mut r = e.client.post(e.url("/api/logout")).header("cookie", cookie);
        if let Some(o) = origin {
            r = r.header("origin", o);
        }
        if let Some(c) = csrf {
            r = r.header("x-csrf-token", c);
        }
        async move { r.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(logout(Some(e.origin()), None, token.clone()).await, 403, "sans jeton CSRF");
    assert_eq!(logout(Some(e.origin()), Some("faux".into()), token.clone()).await, 403, "mauvais jeton CSRF");
    assert_eq!(
        logout(Some("http://evil.example".into()), Some(csrf.clone()), token.clone()).await,
        403,
        "autre origine"
    );
    assert_eq!(logout(None, Some(csrf.clone()), token.clone()).await, 403, "sans Origin");
    // La connexion aussi exige l'origine (CSRF de connexion).
    let r = e
        .client
        .post(e.url("/api/login"))
        .header("content-type", "application/json")
        .header("origin", "http://evil.example")
        .body(json!({ "password": PW }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(e.get("/api/overview", &token).await.0, 200, "session intacte après les refus");
    assert_eq!(logout(Some(e.origin()), Some(csrf), token.clone()).await, 200);
    assert_eq!(e.get("/api/overview", &token).await.0, 401, "session fermée côté serveur");
}

#[tokio::test]
async fn fixation_de_session_impossible() {
    let e = env().await;
    // Un cookie imposé avant la connexion n'ouvre rien et n'est pas repris par le serveur.
    assert_eq!(e.get("/api/overview", "synco_dash=jeton-de-l-attaquant").await.0, 401);
    let r = e
        .client
        .post(e.url("/api/login"))
        .header("origin", e.origin())
        .header("cookie", "synco_dash=jeton-de-l-attaquant")
        .header("content-type", "application/json")
        .body(json!({ "password": PW }).to_string())
        .send()
        .await
        .unwrap();
    let c = r.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(!c.contains("jeton-de-l-attaquant"));
    assert_eq!(e.get("/api/overview", "synco_dash=jeton-de-l-attaquant").await.0, 401);
}

#[tokio::test]
async fn hote_refuse_contre_le_rebinding_dns() {
    let e = env().await;
    let r = e.client.get(e.url("/login")).header("host", "evil.example").send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = e.client.get(e.url("/login")).header("host", format!("localhost:{}", e.addr.port())).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let proxied = env_with(1, vec!["runtime-admin.example.com".into()]).await;
    let r = proxied.client.get(proxied.url("/login")).header("host", "runtime-admin.example.com").send().await.unwrap();
    assert_eq!(r.status(), 200, "hôte déclaré dans allowed_hosts");
}

#[tokio::test]
async fn force_brute_de_bout_en_bout() {
    let e = env().await;
    let attempt = |pw: &'static str| {
        let r = e
            .client
            .post(e.url("/api/login"))
            .header("origin", e.origin())
            .header("content-type", "application/json")
            .body(json!({ "password": pw }).to_string());
        async move { r.send().await.unwrap() }
    };
    for _ in 0..MAX_FAILURES_PER_IP {
        let r = attempt("faux").await;
        assert_eq!(r.status(), 401);
        assert_eq!(json(r).await["error"], "invalid_credentials");
    }
    let r = attempt("faux").await;
    assert_eq!(r.status(), 429);
    assert!(r.headers()["retry-after"].to_str().unwrap().parse::<u64>().unwrap() > 0);
    assert_eq!(attempt(PW_STATIC).await.status(), 429, "même le bon mot de passe est refusé pendant le blocage");
}

const PW_STATIC: &str = "mot de passe du dashboard";

#[tokio::test]
async fn corps_de_connexion_invalide_ou_trop_gros() {
    let e = env().await;
    let post = |body: String, ct: &'static str| {
        let r = e.client.post(e.url("/api/login")).header("origin", e.origin()).header("content-type", ct).body(body);
        async move { r.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(post("pas du json".into(), "application/json").await, 400);
    assert_eq!(post(json!({ "password": "x", "autre": 1 }).to_string(), "application/json").await, 400);
    assert_eq!(post(json!({ "password": PW }).to_string(), "text/plain").await, 400, "type de contenu non JSON");
    assert_eq!(
        post(json!({ "password": "x".repeat(5_000) }).to_string(), "application/json").await,
        400,
        "plus de 1 Kio"
    );
}
