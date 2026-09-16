const tokenInput = document.querySelector("#token");
const token = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
tokenInput.value = token;
window.history.replaceState({}, document.title, window.location.pathname);
async function csrf() {
  const response = await fetch("/csrf", {credentials: "same-origin"});
  return (await response.json()).csrf_token;
}
document.querySelector("#reset").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const response = await fetch("/password/reset", {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": await csrf()},
    body: JSON.stringify(data),
  });
  const body = await response.json();
  alert(body.message || body.detail || "Request completed");
});
