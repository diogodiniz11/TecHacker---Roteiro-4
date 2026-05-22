(function () {
  "use strict";

  const origin = location.hostname;

  function send(type, data) {
    window.postMessage({ __pm: true, type, data }, "*");
  }

  function isThirdParty(url) {
    try {
      return new URL(url, location.href).hostname !== origin;
    } catch (_) { return false; }
  }

  // Hook genérico de método
  function hook(obj, method, category, label) {
    if (!obj || typeof obj[method] !== "function") return;
    const orig = obj[method];
    obj[method] = function (...args) {
      send("fingerprint", { category, method: label || method });
      return orig.apply(this, args);
    };
  }

  // Canvas
  hook(HTMLCanvasElement.prototype, "toDataURL", "canvas");
  hook(HTMLCanvasElement.prototype, "toBlob", "canvas");
  hook(CanvasRenderingContext2D.prototype, "getImageData", "canvas");

  // WebGL
  [WebGLRenderingContext, WebGL2RenderingContext].forEach(Ctx => {
    if (!Ctx) return;
    const orig = Ctx.prototype.getParameter;
    Ctx.prototype.getParameter = function (param) {
      if (param === 0x9245 || param === 0x9246) {
        send("fingerprint", { category: "webgl", method: "getParameter(UNMASKED)" });
      }
      return orig.apply(this, arguments);
    };
    hook(Ctx.prototype, "getExtension", "webgl");
  });

  // AudioContext
  const AC = window.AudioContext || window.webkitAudioContext;
  if (AC) {
    hook(AC.prototype, "createOscillator", "audioContext");
    hook(AC.prototype, "createDynamicsCompressor", "audioContext");
    hook(AC.prototype, "createAnalyser", "audioContext");
  }

  // Web Storage
  function wrapStorage(store, name) {
    if (!store) return;
    const origSet = store.setItem.bind(store);
    store.setItem = function (key, value) {
      send("storage", { type: name, key, size: String(value).length, domain: origin });
      return origSet(key, value);
    };
  }
  try { wrapStorage(localStorage, "localStorage"); } catch (_) {}
  try { wrapStorage(sessionStorage, "sessionStorage"); } catch (_) {}

  // Snapshot do storage já existente
  window.addEventListener("load", () => {
    ["localStorage", "sessionStorage"].forEach(name => {
      try {
        const store = window[name];
        const items = [];
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          items.push({ key, size: (store.getItem(key) || "").length });
        }
        if (items.length) send("storageSnapshot", { type: name, items, domain: origin });
      } catch (_) {}
    });
  });

  // Hijacking: redirecionamentos
  ["replace", "assign"].forEach(method => {
    try {
      const orig = location[method].bind(location);
      location[method] = function (url) {
        if (isThirdParty(url)) send("hijacking", { type: "redirect", method, destination: url });
        return orig(url);
      };
    } catch (_) {}
  });

  const origOpen = window.open;
  window.open = function (url, ...rest) {
    if (url && isThirdParty(url)) send("hijacking", { type: "window.open", destination: url });
    return origOpen.apply(this, [url, ...rest]);
  };

  // Hijacking: scripts injetados
  const SUSPICIOUS = [/beef.*hook/i, /xss/i, /exploit/i, /payload/i];
  new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeName !== "SCRIPT") continue;
        const src = node.src || "";
        if (src && isThirdParty(src)) {
          send("hijacking", { type: "externalScript", src });
        }
        if (SUSPICIOUS.some(p => p.test(src) || p.test((node.textContent || "").slice(0, 300)))) {
          send("hijacking", { type: "suspiciousScript", src: src || "(inline)", snippet: (node.textContent || "").slice(0, 100) });
        }
      }
    }
  }).observe(document.documentElement, { childList: true, subtree: true });

})();
