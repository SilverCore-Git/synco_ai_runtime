//! Tests du proxy `web` : vecteurs `docs/plan/vectors/web-guard.json` (résolveur et transport simulés),
//! adaptateurs de recherche, quotas, révocation, et un aller-retour complet sur un socket Unix avec un
//! faux service de recherche et un faux site **locaux** (aucun appel réseau réel).

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

use super::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../../docs/plan/vectors/web-guard.json")).expect("vecteurs")
}

#[derive(Default)]
struct FakeResolver(HashMap<String, Vec<IpAddr>>);

impl Resolver for FakeResolver {
    fn lookup(&self, host: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, ()>> {
        let r = self.0.get(host).cloned().ok_or(());
        Box::pin(async move { r })
    }
}

/// Réponse simulée : statut, `Location`, `Content-Type`, `Content-Encoding`, taille du corps.
type FakeHop = (u16, Option<String>, Option<String>, Option<String>, usize);

/// Transport simulé : réponse par URL ; enregistre les adresses épinglées reçues.
#[derive(Default)]
struct FakeTransport {
    responses: HashMap<String, FakeHop>,
    seen: Mutex<Vec<(String, Vec<SocketAddr>)>>,
}

impl Transport for FakeTransport {
    fn get(
        &self,
        url: reqwest::Url,
        host: String,
        pinned: Vec<SocketAddr>,
        max: usize,
        _timeout: Duration,
    ) -> BoxFuture<'_, Result<Hop, FetchError>> {
        lock(&self.seen).push((host, pinned));
        let r = self.responses.get(url.as_str()).cloned();
        Box::pin(async move {
            let (status, location, content_type, content_encoding, size) =
                r.unwrap_or((200, None, Some("text/html".into()), None, 2));
            let body = Bytes::from(vec![b'a'; size.min(max.saturating_add(1))]);
            Ok(Hop { status, location, content_type, content_encoding, body })
        })
    }
}

fn ips(v: &Value) -> Vec<IpAddr> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()?.parse().ok()).collect()).unwrap_or_default()
}

fn host_of(u: &str) -> String {
    reqwest::Url::parse(u)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
        .unwrap_or_default()
}

#[tokio::test]
async fn ssrf_des_vecteurs() {
    let v = vectors();
    for case in v["ssrfCases"].as_array().expect("cas") {
        let name = case["name"].as_str().expect("nom");
        let url = case["url"].as_str().expect("url");
        let mut resolver = FakeResolver::default();
        resolver.0.insert(host_of(url), ips(&case["resolved"]));
        let mut transport = FakeTransport::default();
        let mut current = url.to_owned();
        for r in case["redirects"].as_array().into_iter().flatten() {
            let loc = r["location"].as_str().expect("location").to_owned();
            resolver.0.insert(host_of(&loc), ips(&r["resolved"]));
            transport.responses.insert(
                reqwest::Url::parse(&current).expect("url").to_string(),
                (302, Some(loc.clone()), None, None, 0),
            );
            current = loc;
        }
        let synco: BTreeSet<String> =
            case["syncoHosts"].as_array().into_iter().flatten().filter_map(|h| h.as_str().map(str::to_owned)).collect();
        let r = fetch(url, MAX_FETCH_BYTES, &synco, &resolver, &transport).await;
        let got = match &r {
            Ok(_) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(got, case["expect"].as_str().expect("attendu"), "{name}");
        // Toute connexion part vers une adresse contrôlée, jamais vers une adresse refusée.
        for (_, pinned) in lock(&transport.seen).iter() {
            assert!(pinned.iter().all(|a| !ip_refused(a.ip())), "{name}");
        }
    }
}

#[tokio::test]
async fn reponses_des_vecteurs() {
    let v = vectors();
    for case in v["responseCases"].as_array().expect("cas") {
        let name = case["name"].as_str().expect("nom");
        let mut resolver = FakeResolver::default();
        resolver.0.insert("www.exemple.org".into(), vec!["93.184.215.14".parse().expect("ip")]);
        let mut transport = FakeTransport::default();
        let size = usize::try_from(case["size"].as_u64().expect("taille")).expect("taille");
        transport.responses.insert(
            "https://www.exemple.org/doc".into(),
            (
                200,
                None,
                case["contentType"].as_str().map(str::to_owned),
                case["contentEncoding"].as_str().map(str::to_owned),
                size,
            ),
        );
        let r = fetch("https://www.exemple.org/doc", MAX_FETCH_BYTES, &BTreeSet::new(), &resolver, &transport).await;
        let got = match &r {
            Ok(f) => {
                assert_eq!(f.body.len(), size, "{name}");
                "ok"
            }
            Err(e) => e.code(),
        };
        assert_eq!(got, case["expect"].as_str().expect("attendu"), "{name}");
    }
}

#[test]
fn corps_de_recherche_des_vecteurs() {
    let v = vectors();
    for case in v["searchBodyCases"].as_array().expect("cas") {
        let name = case["name"].as_str().expect("nom");
        let ok = serde_json::from_value::<SearchBody>(case["body"].clone()).is_ok_and(|b| b.valid());
        assert_eq!(if ok { "ok" } else { "web_bad_request" }, case["expect"].as_str().expect("attendu"), "{name}");
    }
}

#[test]
fn adresses_supplementaires_refusees() {
    for bad in [
        "64:ff9b::a00:5",      // NAT64 vers 10.0.0.5, check-secrets:allow (adresse refusée par le test)
        "2002:a00:5::1",       // 6to4, check-secrets:allow (adresse refusée par le test)
        "2001:0:4136:e378::1", // Teredo
        "::a00:5",             // IPv4 compatible, check-secrets:allow (adresse refusée par le test)
        "fec0::1",
        "fd00:ec2::254",
        "169.254.169.254",
        "192.0.0.8",
        "0.0.0.0",
        "255.255.255.255",
        "::ffff:127.0.0.1",
    ] {
        assert!(ip_refused(bad.parse().expect("ip")), "{bad}");
    }
    assert!(!ip_refused("93.184.215.14".parse().expect("ip")));
    assert!(!ip_refused("2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().expect("ip")));
    assert!(!addrs_allowed(&[]), "aucune adresse : refus");
}

#[test]
fn url_de_base_des_services() {
    assert!(search_base_allowed(SearchProvider::Staan, "https://api.staan.ai/v2", false));
    assert!(search_base_allowed(SearchProvider::Mojeek, "https://www.mojeek.com", false));
    for bad in [
        "http://api.staan.ai/v2",
        "https://api.staan.ai:8443/v2",
        "https://u:p@api.staan.ai/v2",
        "https://api.staan.ai/v2?x=1",
        "https://localhost/",
        "https://10.0.0.5/",  // check-secrets:allow (adresse refusée par le test)
        "https://searx.lan/", // check-secrets:allow (adresse refusée par le test)
    ] {
        assert!(!search_base_allowed(SearchProvider::Staan, bad, false), "{bad}");
    }
    // SearXNG sur le réseau de l'org : seulement avec `allow_private_host`.
    let lan = "http://searx.lan:8080"; // check-secrets:allow (instance privée explicite du test)
    assert!(!search_base_allowed(SearchProvider::Searxng, lan, false));
    assert!(search_base_allowed(SearchProvider::Searxng, lan, true));
    let ok = WebSettings {
        search: Some(WebSearchSettings {
            provider: "staan".into(),
            base_url: "https://api.staan.ai/v2".into(),
            api_key_file: None,
            api_key_env: Some("STAAN_KEY".into()),
            allow_private_host: false,
        }),
        ..WebSettings::default()
    };
    assert!(validate_settings(&ok).is_ok());
    let mut no_key = ok.clone();
    if let Some(s) = &mut no_key.search {
        s.api_key_env = None;
    }
    assert!(validate_settings(&no_key).is_err(), "Staan exige une clé");
    let mut private_staan = ok.clone();
    if let Some(s) = &mut private_staan.search {
        s.allow_private_host = true;
    }
    assert!(validate_settings(&private_staan).is_err(), "allow_private_host réservé à searxng");
}

fn service(provider: SearchProvider, base: &str, key: Option<&str>) -> SearchService {
    SearchService {
        provider,
        base_url: base.to_owned(),
        key: key.map(|k| Zeroizing::new(k.as_bytes().to_vec())),
        allow_private_host: true,
    }
}

fn body(q: &str, freshness: Option<&str>, lang: Option<&str>, count: Option<u8>) -> SearchBody {
    SearchBody { query: q.into(), freshness: freshness.map(Into::into), lang: lang.map(Into::into), count }
}

#[test]
fn requetes_des_adaptateurs() {
    let b = body("météo paris", Some("week"), Some("fr"), Some(5));
    // 2026-11-25 = 20 782 jours après 1970-01-01.
    let today = 20_782;
    assert_eq!(civil_yyyymmdd(today), "20261125");
    assert_eq!(civil_yyyymmdd(0), "19700101");
    let r = provider_request(&service(SearchProvider::Staan, "https://api.staan.ai/v2", Some("k")), &b, today)
        .expect("staan");
    assert_eq!(r.url.as_str(), "https://api.staan.ai/v2/search/web?q=m%C3%A9t%C3%A9o+paris&market=fr-fr");
    assert_eq!(r.auth_header, Some("authorization"));
    let r = provider_request(&service(SearchProvider::Mojeek, "https://www.mojeek.com", Some("k")), &b, today)
        .expect("mojeek");
    assert_eq!(
        r.url.as_str(),
        "https://www.mojeek.com/search?q=m%C3%A9t%C3%A9o+paris&fmt=json&t=5&lb=FR&since=20261118&api_key=k"
    );
    assert_eq!(r.auth_header, None);
    let r =
        provider_request(&service(SearchProvider::Searxng, "https://searx.example", None), &b, today).expect("searxng");
    assert_eq!(
        r.url.as_str(),
        "https://searx.example/search?q=m%C3%A9t%C3%A9o+paris&format=json&language=fr&time_range=week"
    );
    let r = provider_request(&service(SearchProvider::Brave, "https://api.search.brave.com", Some("k")), &b, today)
        .expect("brave");
    assert_eq!(
        r.url.as_str(),
        "https://api.search.brave.com/res/v1/web/search?q=m%C3%A9t%C3%A9o+paris&count=5&search_lang=fr&freshness=pw"
    );
    assert_eq!(r.auth_header, Some("x-subscription-token"));
    // Jamais de localisation : aucun paramètre de ville ou d'adresse.
    for p in [SearchProvider::Staan, SearchProvider::Mojeek, SearchProvider::Searxng, SearchProvider::Brave] {
        let r = provider_request(&service(p, "https://s.example", Some("k")), &b, today).expect("req");
        assert!(r.url.query_pairs().all(|(k, _)| !["city", "location", "ip", "country"].contains(&k.as_ref())));
    }
}

#[test]
fn normalisation_des_reponses() {
    let staan = json!({ "search_id": "x", "web": { "results": [
        { "title": "T", "url": "https://a.example/1", "snippet": "S", "hostname": "a.example" },
        { "title": "piège", "url": "javascript:alert(1)", "snippet": "x" },
        { "title": "T2", "url": "https://b.example/2", "snippet": "S2" },
    ] } });
    let r = normalize_results(SearchProvider::Staan, &staan, 10).expect("staan");
    assert_eq!(r.len(), 2, "URL non http(s) écartée");
    assert_eq!(r[0], json!({ "title": "T", "url": "https://a.example/1", "snippet": "S" }));
    let mojeek = json!({ "response": { "status": "OK", "results": [{ "title": "M", "url": "https://m.example/", "desc": "D", "date": "2026-11-01" }] } });
    assert_eq!(
        normalize_results(SearchProvider::Mojeek, &mojeek, 10).expect("mojeek")[0],
        json!({ "title": "M", "url": "https://m.example/", "snippet": "D", "age": "2026-11-01" })
    );
    assert!(
        normalize_results(
            SearchProvider::Mojeek,
            &json!({ "response": { "status": "ERROR: Daily Limit Reached" } }),
            10
        )
        .is_err()
    );
    let searx = json!({ "results": [{ "title": "X", "url": "https://x.example/", "content": "C", "publishedDate": "2026-11-20" }] });
    assert_eq!(normalize_results(SearchProvider::Searxng, &searx, 10).expect("searx")[0]["snippet"], "C");
    let brave = json!({ "web": { "results": [{ "title": "B", "url": "https://b.example/", "description": "D", "age": "2 days" }] } });
    assert_eq!(normalize_results(SearchProvider::Brave, &brave, 10).expect("brave")[0]["age"], "2 days");
    // Plafonds : `count`, 10 au plus, 8 Kio (extraits raccourcis puis résultats retirés).
    let many: Vec<Value> = (0..30)
        .map(|i| json!({ "title": "t".repeat(300), "url": format!("https://e.example/{i}"), "snippet": "s".repeat(800) }))
        .collect();
    let r = normalize_results(SearchProvider::Searxng, &json!({ "results": many }), 3).expect("borné");
    assert_eq!(r.len(), 3);
    let r = normalize_results(SearchProvider::Searxng, &json!({ "results": many }), 10).expect("borné");
    assert!(json!({ "results": r }).to_string().len() <= SEARCH_RESULTS_MAX_BYTES);
    assert!(r.iter().all(|x| x["title"].as_str().is_some_and(|t| t.chars().count() <= 200)));
    assert!(normalize_results(SearchProvider::Staan, &json!("x"), 10).is_err());
}

// ---------------------------------------------------------------------------
// Aller-retour sur le socket : faux service de recherche et faux site locaux
// ---------------------------------------------------------------------------

async fn local_server(app: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let addr = l.local_addr().expect("adresse");
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    addr
}

async fn post(socket: &std::path::Path, path: &str, body: &Value) -> (u16, Option<String>, Value, Bytes) {
    let stream = tokio::net::UnixStream::connect(socket).await.expect("connexion");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.expect("http");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "web-proxy")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("requête");
    let resp = sender.send_request(req).await.expect("réponse");
    let status = resp.status().as_u16();
    let final_url = resp.headers().get("x-synco-final-url").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let bytes = resp.into_body().collect().await.expect("corps").to_bytes();
    (status, final_url, serde_json::from_slice(&bytes).unwrap_or(Value::Null), bytes)
}

type Seen = Arc<Mutex<Vec<HashMap<String, String>>>>;

fn headers_of(h: &axum::http::HeaderMap) -> HashMap<String, String> {
    h.iter().map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned())).collect()
}

#[tokio::test]
async fn aller_retour_recherche_lecture_et_revocation() {
    let seen: Seen = Arc::default();
    // Faux Staan : vérifie la clé injectée, rend deux résultats.
    let s2 = Arc::clone(&seen);
    let staan = axum::Router::new().route(
        "/v2/search/web",
        axum::routing::get(move |h: axum::http::HeaderMap, q: axum::extract::RawQuery| {
            let s2 = Arc::clone(&s2);
            async move {
                let mut m = headers_of(&h);
                m.insert("query".into(), q.0.unwrap_or_default());
                lock(&s2).push(m);
                axum::Json(json!({ "web": { "results": [
                    { "title": "Gestion de projet", "url": "https://fr.wikipedia.org/wiki/Gestion_de_projet", "snippet": "…" },
                ] } }))
            }
        }),
    );
    let staan_addr = local_server(staan).await;
    // Faux site : redirection puis page, avec un cookie (jeté) ; note les en-têtes reçus.
    let s3 = Arc::clone(&seen);
    let site = axum::Router::new()
        .route("/r", axum::routing::get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/page")]) }))
        .route(
            "/page",
            axum::routing::get(move |h: axum::http::HeaderMap| {
                let s3 = Arc::clone(&s3);
                async move {
                    lock(&s3).push(headers_of(&h));
                    (
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::SET_COOKIE, "s=1")],
                        "<p>Bonjour</p>",
                    )
                }
            }),
        )
        .route(
            "/gz",
            axum::routing::get(|| async {
                ([(header::CONTENT_TYPE, "text/html"), (header::CONTENT_ENCODING, "gzip")], "x")
            }),
        );
    let site_addr = local_server(site).await;

    let settings = WebSettings::default();
    let mut resolver = FakeResolver::default();
    resolver.0.insert("www.exemple.org".into(), vec!["93.184.215.14".parse().expect("ip")]);
    let transport = ReqwestTransport { connect_to: Some(site_addr) };
    let search = SearchService {
        provider: SearchProvider::Staan,
        base_url: format!("http://{staan_addr}/v2"),
        key: Some(Zeroizing::new(b"cle-de-test".to_vec())),
        allow_private_host: true,
    };
    let proxy = WebProxy::with_parts(Some(search), &settings, Vec::new(), Arc::new(resolver), Arc::new(transport))
        .expect("proxy");
    assert_eq!(proxy.provider(), Some("staan"));
    let dir = tempfile::tempdir().expect("dossier");
    let socket = dir.path().join(WEB_SOCKET_NAME);
    let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
    let task = proxy.serve(listener, socket.clone(), WebRoute { user_id: "u1".into(), window_secs: 1800 });

    // Recherche : clé injectée par le superviseur, résultats normalisés.
    let (status, _, v, _) = post(&socket, "/search", &json!({ "query": "gestion de projet", "lang": "fr" })).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["results"][0]["url"], "https://fr.wikipedia.org/wiki/Gestion_de_projet");
    {
        let s = lock(&seen);
        let first = s.first().expect("appel au service");
        assert_eq!(first.get("authorization").map(String::as_str), Some("Bearer cle-de-test"));
        assert_eq!(first.get("accept-encoding").map(String::as_str), Some("identity"));
        assert_eq!(first.get("query").map(String::as_str), Some("q=gestion+de+projet&market=fr-fr"));
    }
    // Corps strict : champ de localisation refusé sans appel.
    let (status, _, v, _) = post(&socket, "/search", &json!({ "query": "meteo", "city": "Paris" })).await;
    assert_eq!((status, v["error"].as_str()), (400, Some("web_bad_request")));

    // Lecture : redirection suivie, en-têtes imposés, aucun cookie renvoyé.
    let (status, final_url, _, bytes) = post(&socket, "/fetch", &json!({ "url": "http://www.exemple.org/r" })).await;
    assert_eq!(status, 200);
    assert_eq!(final_url.as_deref(), Some("http://www.exemple.org/page"));
    assert_eq!(bytes.as_ref(), b"<p>Bonjour</p>");
    {
        let s = lock(&seen);
        let page = s.last().expect("lecture");
        assert_eq!(page.get("user-agent").map(String::as_str), Some(FETCH_USER_AGENT));
        assert_eq!(page.get("accept-encoding").map(String::as_str), Some("identity"));
        assert_eq!(page.get("accept").map(String::as_str), Some(FETCH_ACCEPT));
        for h in ["cookie", "authorization", "referer", "origin"] {
            assert!(!page.contains_key(h), "{h}");
        }
    }
    let (status, _, v, _) = post(&socket, "/fetch", &json!({ "url": "http://www.exemple.org/gz" })).await;
    assert_eq!((status, v["error"].as_str()), (415, Some("web_unsupported_type")), "rien n'est décompressé");
    let (status, _, v, _) = post(&socket, "/fetch", &json!({ "url": "http://www.exemple.org:8080/page" })).await;
    assert_eq!((status, v["error"].as_str()), (403, Some("web_url_refused")));
    let (status, _, v, _) = post(&socket, "/autre", &json!({})).await;
    assert_eq!((status, v["error"].as_str()), (404, Some("web_path")));

    // Révocation : socket fermé, connexions suivantes refusées.
    assert_eq!(proxy.revoke_user("autre"), 0);
    assert_eq!(proxy.revoke_user("u1"), 1);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(tokio::net::UnixStream::connect(&socket).await.is_err());
}

#[tokio::test]
async fn quotas_et_corps_trop_grand() {
    let settings = WebSettings {
        quotas: WebQuotas { fetch_per_window: 2, fetch_per_worker: 3, ..WebQuotas::default() },
        ..WebSettings::default()
    };
    let mut resolver = FakeResolver::default();
    resolver.0.insert("www.exemple.org".into(), vec!["93.184.215.14".parse().expect("ip")]);
    let transport = Arc::new(FakeTransport::default());
    let dyn_transport: Arc<dyn Transport> = transport.clone();
    let proxy = WebProxy::with_parts(
        Some(service(SearchProvider::Searxng, "http://127.0.0.1:9", None)),
        &settings,
        Vec::new(),
        Arc::new(resolver),
        dyn_transport,
    )
    .expect("proxy");
    let dir = tempfile::tempdir().expect("dossier");
    let socket = dir.path().join(WEB_SOCKET_NAME);
    let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
    let _task = proxy.serve(listener, socket.clone(), WebRoute { user_id: "u1".into(), window_secs: 1 });
    let page = json!({ "url": "https://www.exemple.org/x" });
    for _ in 0..2 {
        assert_eq!(post(&socket, "/fetch", &page).await.0, 200);
    }
    let (status, _, v, _) = post(&socket, "/fetch", &page).await;
    assert_eq!((status, v["error"].as_str()), (429, Some("web_quota")), "fenêtre pleine");
    let before = lock(&transport.seen).len();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(post(&socket, "/fetch", &page).await.0, 200, "nouvelle fenêtre");
    let (status, _, v, _) = post(&socket, "/fetch", &page).await;
    assert_eq!((status, v["error"].as_str()), (429, Some("web_quota")), "plafond du worker");
    assert_eq!(lock(&transport.seen).len(), before.saturating_add(1), "aucun appel sortant au-delà du quota");
    let (status, _, v, _) = post(&socket, "/search", &json!({ "query": "x".repeat(4096) })).await;
    assert_eq!((status, v["error"].as_str()), (400, Some("web_bad_request")), "corps > 4 Kio");
}

#[tokio::test]
async fn des_workers_inactifs_ne_gardent_aucune_place() {
    let mut resolver = FakeResolver::default();
    resolver.0.insert("www.exemple.org".into(), vec!["93.184.215.14".parse().expect("ip")]);
    let proxy = WebProxy::with_parts(
        Some(service(SearchProvider::Searxng, "http://127.0.0.1:9", None)),
        &WebSettings::default(),
        Vec::new(),
        Arc::new(resolver),
        Arc::new(FakeTransport::default()),
    )
    .expect("proxy");
    let dir = tempfile::tempdir().expect("dossier");
    // Huit workers qui n'ouvrent jamais de connexion (autant que de places du runtime).
    let mut idle = Vec::new();
    for i in 0..CONNECTIONS_PER_RUNTIME {
        let socket = dir.path().join(format!("w{i}.sock"));
        let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
        idle.push(proxy.serve(listener, socket, WebRoute { user_id: format!("u{i}"), window_secs: 60 }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let socket = dir.path().join("w9.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
    let _task = proxy.serve(listener, socket.clone(), WebRoute { user_id: "u9".into(), window_secs: 60 });
    let page = json!({ "url": "https://www.exemple.org/x" });
    let served =
        tokio::time::timeout(Duration::from_secs(5), post(&socket, "/fetch", &page)).await.expect("servi à temps");
    assert_eq!(served.0, 200, "le 9e worker est servi");
}

#[tokio::test]
async fn sans_place_la_connexion_recoit_429() {
    let proxy = WebProxy::with_parts(
        Some(service(SearchProvider::Searxng, "http://127.0.0.1:9", None)),
        &WebSettings::default(),
        Vec::new(),
        Arc::new(FakeResolver::default()),
        Arc::new(FakeTransport::default()),
    )
    .expect("proxy");
    let dir = tempfile::tempdir().expect("dossier");
    let socket = dir.path().join(WEB_SOCKET_NAME);
    let listener = tokio::net::UnixListener::bind(&socket).expect("socket");
    let _task = proxy.serve(listener, socket.clone(), WebRoute { user_id: "u1".into(), window_secs: 60 });
    // Deux connexions ouvertes et gardées : les deux places du worker.
    let mut held = Vec::new();
    for _ in 0..CONNECTIONS_PER_WORKER {
        held.push(tokio::net::UnixStream::connect(&socket).await.expect("connexion"));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, _, v, _) = post(&socket, "/search", &json!({ "query": "meteo" })).await;
    assert_eq!((status, v["error"].as_str()), (429, Some("web_quota")));
    drop(held);
}
