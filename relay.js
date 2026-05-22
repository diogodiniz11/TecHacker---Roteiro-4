window.addEventListener("message", event => {
  if (!event.data || !event.data.__pm) return;
  browser.runtime.sendMessage({
    source: "content",
    type: event.data.type,
    data: event.data.data,
  }).catch(() => {});
});
