/*
 * SAMIIR chat widget loader.
 * <script src="https://<console-host>/widget/loader.js" data-key="pk_..." async></script>
 * The chat UI runs inside a sandboxed, cross-origin iframe: the host page cannot read the
 * conversation, and the widget cannot touch the host page. The iframe itself refuses to load
 * on origins that are not approved for this key (CSP frame-ancestors).
 */
(function () {
  var script = document.currentScript;
  if (!script) return;
  var key = script.getAttribute("data-key") || "";
  if (!/^pk_[A-Za-z0-9_-]{16,64}$/.test(key)) return;
  var origin = new URL(script.src).origin;
  var open = false;

  var button = document.createElement("button");
  button.type = "button";
  button.setAttribute("aria-label", "Open chat");
  button.textContent = "Chat";
  Object.assign(button.style, {
    position: "fixed", right: "20px", bottom: "20px", zIndex: "2147483000", border: "0",
    borderRadius: "999px", padding: "12px 18px", background: "#2a78d6", color: "#fff",
    font: "600 14px system-ui, sans-serif", cursor: "pointer", boxShadow: "0 4px 14px rgba(0,0,0,.2)",
  });

  var frame = document.createElement("iframe");
  frame.title = "Chat with us";
  frame.src = origin + "/widget/" + encodeURIComponent(key);
  frame.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
  frame.setAttribute("referrerpolicy", "strict-origin");
  frame.setAttribute("allow", "");
  Object.assign(frame.style, {
    position: "fixed", right: "20px", bottom: "80px", width: "min(380px, calc(100vw - 40px))",
    height: "min(600px, calc(100vh - 120px))", border: "1px solid rgba(0,0,0,.1)",
    borderRadius: "12px", zIndex: "2147483000", display: "none", background: "#fff",
    boxShadow: "0 8px 30px rgba(0,0,0,.2)",
  });

  button.addEventListener("click", function () {
    open = !open;
    frame.style.display = open ? "block" : "none";
    button.textContent = open ? "Close" : "Chat";
    button.setAttribute("aria-label", open ? "Close chat" : "Open chat");
  });
  document.body.appendChild(frame);
  document.body.appendChild(button);
})();
