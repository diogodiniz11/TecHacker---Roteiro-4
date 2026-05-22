"use strict";

const tabs = new Map();

function initTab(id) {
  if (!tabs.has(id)) {
    tabs.set(id, {
      origin: null,
      thirdParty: {},
      cookies: [],
      storage: { localStorage: [], sessionStorage: [] },
      fingerprinting: { canvas: new Set(), webgl: new Set(), audioContext: new Set() },
      hijacking: { scripts: [], redirects: [] },
    });
  }
  return tabs.get(id);
}

function getTab(id) { return tabs.get(id) || initTab(id); }

function hostname(url) {
  try { return new URL(url).hostname; } catch (_) { return null; }
}

function isThirdParty(url, origin) {
  const h = hostname(url);
  if (!h || !origin) return false;
  const norm = s => s.split(".").slice(-2).join(".");
  return norm(h) !== norm(origin);
}

const TYPE_LABELS = {
  script: "script", image: "imagem", stylesheet: "estilo",
  sub_frame: "iframe", xmlhttprequest: "XHR", font: "fonte",
  media: "mídia", websocket: "WebSocket",
};

// Interceptar requisições de rede
browser.webRequest.onBeforeRequest.addListener(details => {
  const { tabId, url, type, originUrl } = details;
  if (tabId < 0) return;
  const data = getTab(tabId);
  const pageOrigin = data.origin || hostname(originUrl);
  if (pageOrigin && isThirdParty(url, pageOrigin)) {
    const host = hostname(url);
    if (!data.thirdParty[host]) data.thirdParty[host] = [];
    data.thirdParty[host].push({ type: TYPE_LABELS[type] || type, url });
  }
}, { urls: ["<all_urls>"] });

// Reset ao navegar
browser.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0) return;
  tabs.delete(details.tabId);
  initTab(details.tabId).origin = hostname(details.url);
});

// Mensagens do content script
browser.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type === "getReport") return handleGetReport();
  if (msg?.source !== "content") return;

  const tabId = sender.tab?.id;
  if (!tabId || tabId < 0) return;
  const data = getTab(tabId);

  if (msg.type === "fingerprint") {
    data.fingerprinting[msg.data.category]?.add(msg.data.method);
  } else if (msg.type === "storage") {
    const list = data.storage[msg.data.type] || [];
    list.push({ key: msg.data.key, size: msg.data.size, domain: msg.data.domain });
    data.storage[msg.data.type] = list;
  } else if (msg.type === "storageSnapshot") {
    const list = data.storage[msg.data.type] || [];
    for (const item of msg.data.items) {
      if (!list.find(i => i.key === item.key))
        list.push({ ...item, domain: msg.data.domain });
    }
    data.storage[msg.data.type] = list;
  } else if (msg.type === "hijacking") {
    const { type } = msg.data;
    if (type === "redirect" || type === "window.open") {
      data.hijacking.redirects.push(msg.data);
    } else {
      data.hijacking.scripts.push(msg.data);
    }
  }
});

// Calcular score
function calcScore(data) {
  let score = 100;
  score -= Math.min(Object.keys(data.thirdParty).length * 3, 30);
  ["canvas", "webgl", "audioContext"].forEach(c => {
    if (data.fingerprinting[c].size > 0) score -= 25;
  });
  const tpCookies = data.cookies.filter(c => !c.firstParty).length;
  score -= Math.min(tpCookies * 4, 20);
  const storageItems = (data.storage.localStorage?.length || 0) + (data.storage.sessionStorage?.length || 0);
  if (storageItems > 0) score -= 5;
  const hijackCount = data.hijacking.scripts.length + data.hijacking.redirects.length;
  score -= Math.min(hijackCount * 10, 10);
  return Math.max(0, score);
}

// Responder ao popup
async function handleGetReport() {
  const activeTabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tabId = activeTabs[0]?.id;
  if (!tabId) return { error: "Nenhuma aba ativa." };

  // Buscar cookies
  const url = activeTabs[0].url;
  const pageHost = hostname(url);
  const allCookies = await browser.cookies.getAll({ url }).catch(() => []);
  const data = getTab(tabId);

  data.cookies = allCookies.map(c => {
    const cDomain = c.domain.replace(/^\./, "");
    const isFirst = cDomain === pageHost || pageHost?.endsWith("." + cDomain) || cDomain.endsWith("." + pageHost);
    return {
      name: c.name,
      domain: c.domain,
      firstParty: isFirst,
      session: c.session,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      superCookieHint: !c.sameSite && c.domain.startsWith(".") && !isFirst,
    };
  });

  return {
    origin: data.origin,
    thirdParty: data.thirdParty,
    cookies: data.cookies,
    storage: data.storage,
    fingerprinting: {
      canvas: [...data.fingerprinting.canvas],
      webgl: [...data.fingerprinting.webgl],
      audioContext: [...data.fingerprinting.audioContext],
    },
    hijacking: data.hijacking,
    score: calcScore(data),
  };
}
