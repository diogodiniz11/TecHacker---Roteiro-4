"use strict";

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
  });
});

function bdg(text, cls) { return `<span class="badge ${cls}">${text}</span>`; }

function typeBadge(type) {
  const map = { script: "b-script", imagem: "b-imagem", iframe: "b-iframe", XHR: "b-xhr" };
  return bdg(type, map[type] || "b-def");
}

function show(listId, emptyId, items) {
  const list = document.getElementById(listId);
  const empty = document.getElementById(emptyId);
  if (!items.length) { empty.style.display = "block"; list.style.display = "none"; return; }
  empty.style.display = "none";
  list.style.display = "flex";
  list.innerHTML = items.map(h => `<li>${h}</li>`).join("");
}

function renderScore(score) {
  const ring = document.getElementById("ring");
  const val = document.getElementById("scoreVal");
  const label = document.getElementById("scoreLabel");
  val.textContent = score;
  ring.classList.remove("yellow", "red");
  if (score >= 80) { label.textContent = "🟢 Privacidade respeitada"; }
  else if (score >= 50) { ring.classList.add("yellow"); label.textContent = "🟡 Privacidade moderada"; }
  else { ring.classList.add("red"); label.textContent = "🔴 Alto risco de rastreamento"; }
}

function renderThirdParty(tp) {
  const items = Object.entries(tp).map(([domain, resources]) => {
    const types = [...new Set(resources.map(r => r.type))];
    return `<div class="row"><span class="main">${domain}</span><div class="badges">${types.map(typeBadge).join("")}</div></div>
            <div class="sub">${resources.length} recurso(s)</div>`;
  });
  show("tp-list", "tp-empty", items);
}

function renderCookies(cookies) {
  const fp = cookies.filter(c => c.firstParty).length;
  const tp = cookies.filter(c => !c.firstParty).length;
  const sess = cookies.filter(c => c.session).length;
  const pers = cookies.filter(c => !c.session).length;
  const sup = cookies.filter(c => c.superCookieHint).length;
  document.getElementById("cookie-stats").innerHTML =
    `<div class="chip">1ª parte <span>${fp}</span></div>` +
    `<div class="chip">3ª parte <span>${tp}</span></div>` +
    `<div class="chip">Sessão <span>${sess}</span></div>` +
    `<div class="chip">Persistente <span>${pers}</span></div>` +
    (sup ? `<div class="chip">⚠️ Supercookie <span>${sup}</span></div>` : "");
  const items = cookies.map(c =>
    `<div class="row"><span class="main">${c.name}</span><div class="badges">
      ${bdg(c.firstParty ? "1ª parte" : "3ª parte", c.firstParty ? "b-1p" : "b-3p")}
      ${bdg(c.session ? "sessão" : "persistente", c.session ? "b-sess" : "b-pers")}
      ${c.superCookieHint ? bdg("supercookie?", "b-super") : ""}
    </div></div><div class="sub">${c.domain}</div>`
  );
  show("cookie-list", "cookie-empty", items);
}

function renderStorage(storage) {
  const items = [];
  for (const [type, entries] of Object.entries(storage)) {
    for (const e of entries) {
      items.push(`<div class="row"><span class="main">${e.key}</span>${bdg(type, "b-def")}</div>
                  <div class="sub">${e.size} bytes · ${e.domain || "—"}</div>`);
    }
  }
  show("storage-list", "storage-empty", items);
}

function renderFingerprint(fp) {
  const labels = { canvas: "Canvas", webgl: "WebGL", audioContext: "AudioContext" };
  const cls = { canvas: "b-canvas", webgl: "b-webgl", audioContext: "b-audio" };
  const items = [];
  for (const [cat, methods] of Object.entries(fp)) {
    for (const m of methods) {
      items.push(`<div class="row"><span class="main">${m}</span>${bdg(labels[cat], cls[cat])}</div>
                  <div class="sub">Técnica de fingerprinting detectada</div>`);
    }
  }
  show("fp-list", "fp-empty", items);
}

function renderHijacking(hj) {
  const items = [];
  for (const s of hj.scripts || []) {
    const level = s.type === "suspiciousScript" ? bdg("⚠️ suspeito", "b-danger") : bdg("externo", "b-warn");
    items.push(`<div class="row"><span class="main">${s.src || "(inline)"}</span>${level}</div>
                <div class="sub">${s.snippet ? s.snippet.slice(0, 60) + "…" : "Script externo de terceiro"}</div>`);
  }
  for (const r of hj.redirects || []) {
    items.push(`<div class="row"><span class="main">${r.method || r.type}</span>${bdg("redirecionamento", "b-danger")}</div>
                <div class="sub">${r.destination}</div>`);
  }
  show("hj-list", "hj-empty", items);
}

async function load() {
  try {
    const r = await browser.runtime.sendMessage({ type: "getReport" });
    if (!r || r.error) { document.getElementById("scoreVal").textContent = "!"; return; }
    document.getElementById("origin").textContent = r.origin || "—";
    renderScore(r.score);
    renderThirdParty(r.thirdParty || {});
    renderCookies(r.cookies || []);
    renderStorage(r.storage || {});
    renderFingerprint(r.fingerprinting || {});
    renderHijacking(r.hijacking || {});
  } catch (e) { console.error(e); }
}

load();
