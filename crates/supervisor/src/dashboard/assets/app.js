"use strict";
/* Tableau de bord : tout le texte est inséré avec textContent, jamais comme HTML. */
(function () {
  var main = document.getElementById("main");
  var csrf = "";
  var confirming = false;
  var timer = null;
  var sessionsState = { sort: "started", desc: true, offset: 0, limit: 25, state: "", user: "", provider: "", period: "0", errorsOnly: false };
  var totalsState = { by: "user", period: "0" };
  var STATES = { idle: "Terminé", running: "En cours", queued: "En attente", awaiting_confirmation: "Confirmation demandée",
    awaiting_user: "Réponse attendue", awaiting_key: "Clé attendue", awaiting_client_tool: "Outil client", failed: "Échec",
    cancelled: "Annulé", other: "Autre" };

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") node.className = attrs[k]; else if (k === "text") node.textContent = attrs[k]; else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { node.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return node;
  }
  function card(label, value, cls) {
    return el("div", { class: "card" }, [el("div", { class: "label", text: label }), el("div", { class: "value " + (cls || ""), text: value })]);
  }
  function nf(n) { return Number(n || 0).toLocaleString("fr-FR"); }
  function eur(micro) {
    return (Number(micro || 0) / 1e6).toLocaleString("fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 4 }) + " €";
  }
  function bytes(n) {
    n = Number(n || 0);
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " Gio";
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " Mio";
    if (n >= 1024) return (n / 1024).toFixed(0) + " Kio";
    return n + " o";
  }
  function pm(v) { return (Number(v || 0) / 10).toFixed(1) + " %"; }
  function dur(s) {
    s = Number(s || 0);
    if (s < 60) return s + " s";
    if (s < 3600) return Math.floor(s / 60) + " min " + (s % 60) + " s";
    return Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min";
  }
  function when(t) { return t ? new Date(t * 1000).toLocaleString("fr-FR") : "—"; }
  function stateLabel(s) { return STATES[s] || s; }
  function group4(h) { return (String(h || "").match(/.{1,4}/g) || []).join(" "); }

  function api(path, opts) {
    return fetch(path, Object.assign({ credentials: "same-origin" }, opts || {})).then(function (res) {
      if (res.status === 401) { window.location.href = "/login"; return Promise.reject(new Error("401")); }
      if (!res.ok) return Promise.reject(new Error(String(res.status)));
      return res.json();
    });
  }
  function periodFrom(p) {
    var days = Number(p);
    return days > 0 ? Math.floor(Date.now() / 1000) - days * 86400 : null;
  }
  function qs(obj) {
    var parts = [];
    Object.keys(obj).forEach(function (k) {
      var v = obj[k];
      if (v !== null && v !== undefined && v !== "" && v !== false) parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    });
    return parts.length ? "?" + parts.join("&") : "";
  }
  function fail(err) {
    main.replaceChildren(el("p", { class: "error", text: "Chargement impossible (" + err.message + ")." }));
  }

  // --- Vue d'ensemble ---
  function renderOverview(o) {
    var kids = [];
    kids.push(el("h2", { text: "Runtime" }));
    var g1 = el("div", { class: "grid" }, [
      card("Appairage", o.paired ? "Appairé" : "Non appairé", o.paired ? "ok" : "warn"),
      card("API Synco", o.apiConnected ? "Connectée" : "Hors ligne", o.apiConnected ? "ok" : "bad"),
      card("Version", o.version),
      card("Lanceur de workers", o.launcher),
      card("Organisation", o.orgId || "—"),
      card("Identifiant du runtime", o.runtimeId)
    ]);
    kids.push(g1);
    kids.push(el("h2", { text: "Empreinte de la clé" }));
    kids.push(el("div", { class: "card" }, [
      el("div", { class: "fpr", text: o.fingerprint }),
      el("div", { class: "muted", text: "À comparer avec celle affichée par Synco lors de l'appairage." })
    ]));
    if (!o.paired && o.pairingCode) {
      kids.push(el("div", { class: "card" }, [el("div", { class: "label", text: "Code d'appairage" }), el("div", { class: "value mono", text: o.pairingCode })]));
    }
    kids.push(el("h2", { text: "Activité" }));
    var h = o.host || {};
    var memUsed = h.memTotal && h.memAvailable ? bytes(h.memTotal - h.memAvailable) + " / " + bytes(h.memTotal) : "—";
    kids.push(el("div", { class: "grid" }, [
      card("Workers actifs", o.activeWorkers + " / " + o.maxWorkers),
      card("Conversations en attente", nf(o.queued)),
      card("CPU de la machine", h.cpuPermille === null || h.cpuPermille === undefined ? "—" : pm(h.cpuPermille)),
      card("Charge (1 min)", h.load1Centi === null || h.load1Centi === undefined ? "—" : (h.load1Centi / 100).toFixed(2) + " sur " + h.cpus + " cœurs"),
      card("RAM de la machine", memUsed),
      card("RAM des workers", bytes(o.activity.workersMem))
    ]));
    kids.push(el("h2", { text: "Coût estimé" }));
    kids.push(el("div", { class: "grid" }, [
      card("Aujourd'hui (UTC)", eur(o.costs.day)), card("7 derniers jours", eur(o.costs.week)), card("30 derniers jours", eur(o.costs.month))
    ]));
    if (o.memberKeyChanges && o.memberKeyChanges.length) {
      kids.push(el("h2", { text: "Clés de membres refusées" }));
      kids.push(el("p", { class: "error", text: "La clé de chiffrement de ces membres a changé sans preuve signée : le runtime refuse de créer des salons tant que la clé n'est pas acceptée. Le serveur Synco a peut-être substitué cette clé." }));
      kids.push(el("p", { class: "muted", text: "Synco n'affiche pas encore au membre l'empreinte de sa propre clé : aucune comparaison d'empreinte n'est possible aujourd'hui. Contactez le membre par un autre canal que Synco et demandez-lui s'il a réinitialisé ou renouvelé son chiffrement, et quand (comparez avec la date « Vue le »). N'acceptez que s'il le confirme ; sinon laissez la clé refusée. Les empreintes ci-dessous servent à reconnaître une même clé d'une alerte à l'autre." }));
      var mrows = o.memberKeyChanges.map(function (c) {
        var cell = el("td", {});
        var ask = el("button", { class: "btn", type: "button", text: "Accepter cette clé…" });
        ask.addEventListener("click", function () {
          var yes = el("button", { class: "btn", type: "button", text: "Confirmer : empreinte vérifiée avec le membre" });
          var no = el("button", { class: "btn", type: "button", text: "Annuler" });
          no.addEventListener("click", function () { confirming = false; cell.replaceChildren(ask); });
          yes.addEventListener("click", function () {
            yes.disabled = true;
            confirming = false;
            api("/api/member-keys/accept", {
              method: "POST",
              headers: { "content-type": "application/json", "x-csrf-token": csrf },
              body: JSON.stringify({ userId: c.userId, fingerprint: c.fingerprint })
            }).then(load).catch(function (e) { if (e.message !== "401") fail(e); });
          });
          // Pas de rafraîchissement automatique pendant la confirmation.
          confirming = true;
          cell.replaceChildren(yes, no);
        });
        cell.appendChild(ask);
        return el("tr", {}, [
          el("td", { class: "mono", text: c.userId }),
          el("td", { class: "mono", text: group4(c.pinned) }),
          el("td", { class: "mono", text: group4(c.presented) }),
          el("td", { text: when(c.seen) }),
          cell
        ]);
      });
      var mhead = el("tr", {}, ["Membre", "Empreinte épinglée", "Empreinte proposée", "Vue le", ""].map(function (h) { return el("th", { text: h }); }));
      kids.push(el("div", { class: "tablewrap" }, [el("table", {}, [el("thead", {}, [mhead]), el("tbody", {}, mrows)])]));
    }
    kids.push(el("h2", { text: "Alertes récentes" }));
    if (!o.alerts.length) {
      kids.push(el("p", { class: "muted", text: "Aucune alerte." }));
    } else {
      var rows = o.alerts.slice().reverse().map(function (a) { return el("tr", {}, [el("td", { text: when(a[0]) }), el("td", { class: "mono", text: a[1] })]); });
      kids.push(el("div", { class: "tablewrap" }, [el("table", {}, [el("tbody", {}, rows)])]));
    }
    kids.push(el("p", { class: "muted", text: "Historique local : " + nf(o.activity.historyRuns) + " exécutions, conservé " + o.retentionDays + " jours. Les coûts sont des estimations calculées depuis le tarif configuré." }));
    main.replaceChildren.apply(main, kids);
  }

  // --- Sessions ---
  var COLUMNS = [
    ["Début", "started", false], ["Utilisateur", "user", false], ["Fournisseur", null, false], ["État", "status", false],
    ["Durée", "duration", true], ["Étapes", "steps", true], ["Outils", "toolCalls", true], ["Tokens e/s/r", "tokens", true],
    ["Coût", "cost", true], ["RAM pic / moy.", "memPeak", true], ["CPU moy. / pic", "cpuAvg", true], ["Erreurs", "errors", true]
  ];
  function sessionsQuery() {
    var s = sessionsState;
    return qs({ sort: s.sort, desc: s.desc ? "true" : "false", limit: s.limit, offset: s.offset, state: s.state, user: s.user,
      provider: s.provider, from: periodFrom(s.period), errorsOnly: s.errorsOnly ? "true" : "" });
  }
  function sessionRow(s) {
    var link = el("a", { href: "#/session/" + encodeURIComponent(s.sessionId), text: when(s.started) });
    var cls = s.status === "failed" ? "bad" : s.active ? "ok" : "";
    var res = s.measured ? bytes(s.memPeak) + " / " + bytes(s.memAvg) : "non mesuré";
    var cpu = s.measured ? pm(s.cpuAvgPm) + " / " + pm(s.cpuPeakPm) : "non mesuré";
    return el("tr", {}, [
      el("td", {}, [link]), el("td", { class: "mono", text: s.userId }), el("td", { text: s.provider + " · " + s.model }),
      el("td", { class: cls, text: s.active ? "En cours" : stateLabel(s.status) }), el("td", { class: "num", text: dur(s.durationSecs) }),
      el("td", { class: "num", text: nf(s.steps) }), el("td", { class: "num", text: nf(s.toolCalls) }),
      el("td", { class: "num", text: nf(s.promptTokens) + " / " + nf(s.completionTokens) + " / " + nf(s.reasoningTokens) }),
      el("td", { class: "num", text: eur(s.costMicro) }), el("td", { class: "num", text: res }), el("td", { class: "num", text: cpu }),
      el("td", { class: "num " + (s.errors ? "bad" : ""), text: nf(s.errors) })
    ]);
  }
  function filterBox() {
    var s = sessionsState;
    function select(label, key, options) {
      var sel = el("select", {}, options.map(function (o) { return el("option", { value: o[0], text: o[1] }); }));
      sel.value = s[key];
      sel.addEventListener("change", function () { s[key] = sel.value; s.offset = 0; load(); });
      return el("label", {}, [label, sel]);
    }
    function input(label, key) {
      var inp = el("input", { type: "text", maxlength: "64" });
      inp.value = s[key];
      inp.addEventListener("change", function () { s[key] = inp.value.trim(); s.offset = 0; load(); });
      return el("label", {}, [label, inp]);
    }
    var errs = el("input", { type: "checkbox" });
    errs.checked = s.errorsOnly;
    errs.addEventListener("change", function () { s.errorsOnly = errs.checked; s.offset = 0; load(); });
    return el("div", { class: "filters" }, [
      select("État", "state", [["", "Tous"], ["active", "En cours"], ["ended", "Terminées"], ["failed", "Échec"], ["idle", "Terminé sans erreur"], ["cancelled", "Annulé"]]),
      input("Utilisateur", "user"), input("Fournisseur", "provider"),
      select("Période", "period", [["0", "Tout"], ["1", "24 heures"], ["7", "7 jours"], ["30", "30 jours"]]),
      el("label", {}, [el("span", { text: "Erreurs seulement" }), errs])
    ]);
  }
  var filterNode = null;
  function renderSessions(page) {
    var s = sessionsState;
    if (!filterNode) filterNode = filterBox();
    var head = el("tr", {}, COLUMNS.map(function (c) {
      var th = el("th", { class: c[2] ? "num" : "" });
      if (!c[1]) { th.textContent = c[0]; return th; }
      if (s.sort === c[1]) th.setAttribute("aria-sort", s.desc ? "descending" : "ascending");
      var b = el("button", { type: "button", text: c[0] });
      b.addEventListener("click", function () {
        if (s.sort === c[1]) s.desc = !s.desc; else { s.sort = c[1]; s.desc = true; }
        s.offset = 0; load();
      });
      th.appendChild(b);
      return th;
    }));
    var body = page.items.length ? page.items.map(sessionRow) : [el("tr", {}, [el("td", { colspan: String(COLUMNS.length), class: "muted", text: "Aucune session." })])];
    var prev = el("button", { type: "button", class: "btn", text: "Précédent" });
    var next = el("button", { type: "button", class: "btn", text: "Suivant" });
    prev.disabled = s.offset === 0;
    next.disabled = s.offset + s.limit >= page.total;
    prev.addEventListener("click", function () { s.offset = Math.max(0, s.offset - s.limit); load(); });
    next.addEventListener("click", function () { s.offset += s.limit; load(); });
    var pager = el("div", { class: "pager" }, [prev, next, el("span", { class: "muted", text: nf(page.total) + " session(s)" })]);
    main.replaceChildren(el("h2", { text: "Sessions" }), filterNode,
      el("div", { class: "tablewrap" }, [el("table", {}, [el("thead", {}, [head]), el("tbody", {}, body)])]), pager);
  }

  // --- Détail ---
  function entryRow(e) {
    var t = when(e.t), kind = "", info = "";
    if (e.k === "start") { kind = "Lancement"; }
    else if (e.k === "status") { kind = "État"; info = stateLabel(e.status) + (e.reason ? " (" + e.reason + ")" : ""); }
    else if (e.k === "metrics") {
      kind = "Mesure";
      info = "tour " + e.turn + " : +" + e.steps + " étape(s), +" + e.toolCalls + " outil(s)" + (e.toolErrors ? " dont " + e.toolErrors + " en erreur" : "") +
        ", +" + nf(e.prompt) + " / " + nf(e.completion) + " / " + nf(e.reasoning) + " tokens, +" + eur(e.costMicro) + ", durée du tour " + dur(Math.round(e.turnMs / 1000));
    }
    else if (e.k === "done") { kind = "Fin annoncée"; info = e.reason; }
    else if (e.k === "end") { kind = "Fin du processus"; info = e.exit + (e.crashed ? " (anormale)" : ""); }
    return el("tr", {}, [el("td", { text: t }), el("td", { text: kind }), el("td", { text: info })]);
  }
  function renderDetail(d) {
    var s = d.session;
    var kids = [el("p", {}, [el("a", { href: "#/sessions", text: "← Sessions" })]),
      el("h2", { text: "Session " + s.sessionId })];
    kids.push(el("div", { class: "grid" }, [
      card("Utilisateur", s.userId), card("Fournisseur", s.provider + " · " + s.model), card("État", s.active ? "En cours" : stateLabel(s.status)),
      card("Durée", dur(s.durationSecs)), card("Exécutions", nf(s.runs)), card("Étapes / outils", nf(s.steps) + " / " + nf(s.toolCalls)),
      card("Tokens e/s/r", nf(s.promptTokens) + " / " + nf(s.completionTokens) + " / " + nf(s.reasoningTokens)), card("Coût estimé", eur(s.costMicro)),
      card("RAM pic / moyenne", s.measured ? bytes(s.memPeak) + " / " + bytes(s.memAvg) : "non mesuré"),
      card("CPU moyen / pic", s.measured ? pm(s.cpuAvgPm) + " / " + pm(s.cpuPeakPm) : "non mesuré"), card("Erreurs", nf(s.errors), s.errors ? "bad" : "")
    ]));
    kids.push(el("p", { class: "muted", text: "Chronologie sans contenu : ni texte, ni arguments, ni résultats d'outils." }));
    d.runs.forEach(function (r, i) {
      var title = "Exécution " + (i + 1) + " · " + when(r.started) + (r.interrupted ? " · interrompue" : "") + (r.crashed ? " · fin anormale" : "");
      kids.push(el("h2", { text: title }));
      var rows = r.timeline.length ? r.timeline.map(entryRow) : [el("tr", {}, [el("td", { colspan: "3", class: "muted", text: "Chronologie indisponible." })])];
      kids.push(el("div", { class: "tablewrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", { text: "Heure" }), el("th", { text: "Type" }), el("th", { text: "Détail" })])]), el("tbody", {}, rows)])]));
      if (r.timelineDropped) kids.push(el("p", { class: "muted", text: nf(r.timelineDropped) + " entrée(s) au-delà du plafond non conservées." }));
    });
    main.replaceChildren.apply(main, kids);
  }

  // --- Totaux ---
  function renderTotals(rows) {
    var t = totalsState;
    function select(label, key, options) {
      var sel = el("select", {}, options.map(function (o) { return el("option", { value: o[0], text: o[1] }); }));
      sel.value = t[key];
      sel.addEventListener("change", function () { t[key] = sel.value; load(); });
      return el("label", {}, [label, sel]);
    }
    var body = rows.length ? rows.map(function (r) {
      return el("tr", {}, [el("td", { class: "mono", text: r.key }), el("td", { class: "num", text: nf(r.sessions) }),
        el("td", { class: "num", text: nf(r.promptTokens) + " / " + nf(r.completionTokens) + " / " + nf(r.reasoningTokens) }),
        el("td", { class: "num", text: nf(r.toolCalls) }), el("td", { class: "num", text: nf(r.errors) }), el("td", { class: "num", text: eur(r.costMicro) })]);
    }) : [el("tr", {}, [el("td", { colspan: "6", class: "muted", text: "Aucune donnée." })])];
    var head = el("tr", {}, [t.by === "user" ? "Utilisateur" : "Fournisseur", "Sessions", "Tokens e/s/r", "Outils", "Erreurs", "Coût estimé"].map(function (h, i) {
      return el("th", { class: i ? "num" : "", text: h });
    }));
    main.replaceChildren(el("h2", { text: "Totaux" }),
      el("div", { class: "filters" }, [select("Regrouper par", "by", [["user", "Utilisateur"], ["provider", "Fournisseur LLM"]]),
        select("Période", "period", [["0", "Tout"], ["1", "24 heures"], ["7", "7 jours"], ["30", "30 jours"]])]),
      el("div", { class: "tablewrap" }, [el("table", {}, [el("thead", {}, [head]), el("tbody", {}, body)])]));
  }

  // --- Routage ---
  function route() {
    var h = window.location.hash || "#/";
    var m = /^#\/session\/(.+)$/.exec(h);
    if (m) {
      try {
        return { view: "detail", id: decodeURIComponent(m[1]) };
      } catch (e) {
        return { view: "overview" };
      }
    }
    if (h === "#/sessions") return { view: "sessions" };
    if (h === "#/totals") return { view: "totals" };
    return { view: "overview" };
  }
  function load() {
    var r = route();
    document.querySelectorAll("#nav a").forEach(function (a) {
      var active = a.getAttribute("data-view") === (r.view === "detail" ? "sessions" : r.view);
      if (active) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    var p;
    if (r.view === "overview") p = api("/api/overview").then(renderOverview);
    else if (r.view === "sessions") p = api("/api/sessions" + sessionsQuery()).then(renderSessions);
    else if (r.view === "totals") p = api("/api/totals" + qs({ by: totalsState.by, from: periodFrom(totalsState.period) })).then(renderTotals);
    else p = api("/api/sessions/" + encodeURIComponent(r.id)).then(renderDetail);
    return p.then(function () {
      document.getElementById("updated").textContent = "Mis à jour à " + new Date().toLocaleTimeString("fr-FR");
    }).catch(function (e) { if (e.message !== "401") fail(e); });
  }
  window.addEventListener("hashchange", function () { filterNode = null; confirming = false; load(); });
  document.getElementById("logout").addEventListener("click", function () {
    fetch("/api/logout", { method: "POST", credentials: "same-origin", headers: { "x-csrf-token": csrf } }).then(function () {
      window.location.href = "/login";
    });
  });
  api("/api/session").then(function (s) { csrf = s.csrf || ""; return load(); });
  timer = window.setInterval(function () {
    if (!document.hidden && !confirming && !(document.activeElement && /^(INPUT|SELECT)$/.test(document.activeElement.tagName))) load();
  }, 5000);
  void timer;
})();
