"use strict";
(function () {
  var form = document.getElementById("form");
  var message = document.getElementById("message");
  var button = document.getElementById("submit");
  function show(text) {
    message.textContent = text;
    message.hidden = false;
  }
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    message.hidden = true;
    button.disabled = true;
    var password = document.getElementById("password").value;
    fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ password: password })
    }).then(function (res) {
      if (res.ok) {
        window.location.href = "/";
        return;
      }
      if (res.status === 429) {
        var wait = Number(res.headers.get("Retry-After")) || 900;
        show("Trop de tentatives. Réessayez dans " + Math.ceil(wait / 60) + " min.");
      } else if (res.status === 503) {
        show("Aucun mot de passe n'est défini : lancez « synco-ai-runtime dashboard-password ».");
      } else if (res.status === 401) {
        show("Mot de passe incorrect.");
      } else {
        show("Connexion impossible (" + res.status + ").");
      }
    }).catch(function () {
      show("Le runtime est injoignable.");
    }).then(function () {
      button.disabled = false;
      document.getElementById("password").value = "";
    });
  });
})();
