const token = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
window.history.replaceState({}, document.title, window.location.pathname);
fetch("/auth/verify-email", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({token_value: token}),
}).then(async (response) => {
  const body = await response.json();
  document.querySelector("#status").textContent = body.message || body.detail || "Request completed";
});
