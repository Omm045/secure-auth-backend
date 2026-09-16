const passwordInputs = [document.querySelector("#signup-password"), document.querySelector("#reset-password")];
const strength = document.querySelector("#strength");
const resetToken = document.querySelector("#reset-token");
if (resetToken) {
  resetToken.value = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
  window.history.replaceState({}, document.title, window.location.pathname);
}
passwordInputs.forEach((input) => {
  if (input) input.addEventListener("input", () => {
    if (strength && input.id === "signup-password") strength.value = Math.min(4, Math.floor(input.value.length / 8));
  });
});
async function csrf() {
  const response = await fetch("/csrf", { credentials: "same-origin" });
  if (!response.ok) throw new Error("Unable to initialize CSRF protection");
  return (await response.json()).csrf_token;
}
async function submitForm(form, url) {
  const data = Object.fromEntries(new FormData(form));
  const headers = {"Content-Type": "application/json"};
  if (url === "/password/reset") headers["X-CSRF-Token"] = await csrf();
  const response = await fetch(url, { method: "POST", headers, credentials: "same-origin", body: JSON.stringify(data) });
  const body = await response.json();
  alert(body.message || body.detail || "Request completed");
}
const signup = document.querySelector("#signup");
if (signup) signup.addEventListener("submit", (event) => { event.preventDefault(); submitForm(signup, "/auth/register"); });
const reset = document.querySelector("#reset");
if (reset) reset.addEventListener("submit", (event) => { event.preventDefault(); submitForm(reset, "/password/reset"); });
