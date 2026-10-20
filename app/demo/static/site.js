"use strict";

// The customer site. It shows the visitor's own words and the replies, and nothing about the walls:
// the server sends nothing else to this page. Everything is put on the page with textContent, never
// as HTML, because a reply can hold whatever a model wrote.
//
// The chat is updated in place: a poll adds the bubbles that are new and leaves the others alone, so
// the scroll position, the text being typed and what a screen reader has read stay as they are.

const MAX_TEXT = 2000;
const ROBOT = "/static/volt.svg";

const $ = (id) => document.getElementById(id);
const els = {
  error: $("error"), widget: $("widget"), launcher: $("launcher"), minimise: $("minimise"),
  signin: $("signin"), people: $("people"), chat: $("chat"), meImg: $("me-img"), meName: $("me-name"),
  signout: $("signout"), log: $("log"), form: $("form"), text: $("text"), send: $("send"), honest: $("honest"),
};

let state = null;
let csrf = "";
let timer = null;
let sending = false;
let signature = "";
let shownCustomer = null;
const rows = new Map(); // "u12" / "b12" / "t12" -> the element of that bubble

const PROBLEMS = {
  database: "The service is not answering. Try again in a moment.",
  ticket_limit: "That is enough for one visit. Switch customer to start again.",
  busy: "Volt is still working on your earlier messages. Wait for the replies first.",
  rate: "Too many messages at once. Wait a moment.",
  length: "A message needs 1 to 2000 characters.",
  too_big: "That message is too big.",
  csrf: "The page was out of date. Reload it and try again.",
  signin: "Your visit ended. Choose a customer again.",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function avatar(src, alt) {
  const img = el("img");
  img.src = src;
  img.alt = alt || "";
  img.width = 28;
  img.height = 28;
  return img;
}

async function api(path, options) {
  const init = { credentials: "same-origin", headers: {}, ...options };
  if (init.body !== undefined) {
    init.headers = { "Content-Type": "application/json", "X-CSRF-Token": csrf, ...init.headers };
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(path, init);
  let body = null;
  try { body = await response.json(); } catch (_) { /* no body */ }
  return { ok: response.ok, status: response.status, body };
}

function showError(message) {
  els.error.textContent = message || "";
  els.error.hidden = !message;
}

async function refresh() {
  clearTimeout(timer);
  let result;
  try {
    result = await api("/api/state");
  } catch (_) {
    showError("Cannot reach the service.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  if (!result.ok) {
    showError(PROBLEMS[result.body && result.body.error] || "Something went wrong.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  showError("");
  const text = JSON.stringify(result.body);
  const changed = text !== signature;
  signature = text;
  state = result.body;
  csrf = state.csrf || "";
  if (changed) render();
  const waiting = (state.messages || []).some((m) => !m.reply);
  timer = setTimeout(refresh, waiting ? 1500 : 6000);
}

document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });

function render() {
  const signedIn = state.customer !== null;
  els.signin.hidden = signedIn;
  els.chat.hidden = !signedIn;
  if (state.customer !== shownCustomer) {
    rows.clear();
    els.log.replaceChildren();
    shownCustomer = state.customer;
  }
  if (!signedIn) { renderPeople(); return; }
  const me = state.customers.find((c) => c.id === state.customer);
  els.meName.textContent = me ? me.name : "Customer";
  els.meImg.src = (me && me.avatar) || ROBOT;
  renderLog(me);
}

function renderPeople() {
  els.people.replaceChildren();
  for (const person of state.customers) {
    const button = el("button", "person");
    button.type = "button";
    if (person.avatar) { const img = avatar(person.avatar, ""); img.width = 40; img.height = 40; button.append(img); }
    const label = el("div");
    label.append(el("strong", "", person.name), el("span", "", "Customer"));
    button.append(label);
    button.addEventListener("click", () => signIn(person.id));
    els.people.append(button);
  }
}

// A reply that is the account's JSON comes with a card from the server (textContent only, fixed labels).
function cardBody(card) {
  const body = el("div", "bubble");
  if (card.intro) body.append(el("p", "intro", card.intro));
  const list = el("dl", "card-list");
  for (const [label, value] of card.rows) {
    list.append(el("dt", "", String(label)), el("dd", "", String(value)));
  }
  body.append(list);
  return body;
}

function bubble(kind, who, text, card) {
  const row = el("div", "msg " + kind);
  const body = card ? cardBody(card) : el("div", "bubble", text);
  if (kind === "mine") row.append(body, avatar(who.avatar || ROBOT, who.name || ""));
  else row.append(avatar(ROBOT, ""), body);
  return row;
}

function renderLog(me) {
  const near = els.log.scrollHeight - els.log.scrollTop - els.log.clientHeight < 40;
  if (!rows.has("hello")) {
    const hello = bubble("bot", {}, "Hi " + (me ? me.name.split(" ")[0] : "there") + ", I am Volt. How can I help?");
    rows.set("hello", hello);
    els.log.append(hello);
  }
  const who = me || {};
  let added = false;
  for (const m of state.messages || []) {
    if (!rows.has("u" + m.id)) {
      const row = bubble("mine", who, m.text);
      rows.set("u" + m.id, row);
      els.log.append(row);
      added = true;
    }
    const typing = rows.get("t" + m.id);
    if (!m.reply && !typing) {
      const row = bubble("bot typing", {}, "Volt is typing…");
      rows.set("t" + m.id, row);
      els.log.append(row);
      added = true;
    }
    if (m.reply && !rows.has("b" + m.id)) {
      const row = bubble("bot", {}, m.reply, m.card);
      rows.set("b" + m.id, row);
      if (typing) { typing.replaceWith(row); rows.delete("t" + m.id); } else els.log.append(row);
      added = true;
    }
  }
  if (added && near) els.log.scrollTop = els.log.scrollHeight;
}

async function signIn(id) {
  const result = await api("/api/signin", { method: "POST", body: { customer: id } });
  if (!result.ok) { showError(PROBLEMS[result.body && result.body.error] || "Could not sign in."); return; }
  showError("");
  await refresh();
  els.text.focus();
}

els.signout.addEventListener("click", async () => {
  await api("/api/signout", { method: "POST", body: {} });
  signature = "";
  await refresh();
});

async function submit() {
  if (sending) return;
  const text = els.text.value;
  if (!text.trim()) return;
  if (text.length > MAX_TEXT) { showError(PROBLEMS.length); return; }
  sending = true;
  els.send.disabled = true;
  try {
    const result = await api("/api/message", { method: "POST", body: { text } });
    if (!result.ok) { showError(PROBLEMS[result.body && result.body.error] || "Could not send that."); return; }
    showError("");
    els.text.value = "";
    await refresh();
  } finally {
    sending = false;
    els.send.disabled = false;
    els.text.focus();
  }
}

els.form.addEventListener("submit", (event) => { event.preventDefault(); submit(); });
els.text.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); submit(); }
});
els.honest.addEventListener("click", () => { els.text.value = els.honest.textContent; submit(); });

function setOpen(open) {
  els.widget.hidden = !open;
  els.launcher.hidden = open;
  els.minimise.setAttribute("aria-expanded", String(open));
  (open ? els.text : els.launcher).focus();
}
els.minimise.addEventListener("click", () => setOpen(false));
els.launcher.addEventListener("click", () => setOpen(true));

refresh();
