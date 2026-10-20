"use strict";

// The presenter view. The chat is site.js; this file adds the brain switch, the five attack chips
// and the cards of what the walls did. Everything is put on the page with textContent, never as
// HTML. The server sends only fixed phrases; this file adds nothing from the records.

const $ = (id) => document.getElementById(id);
const els = {
  problem: $("problem"), blocked: $("c-blocked"), waiting: $("c-waiting"), kill: $("c-kill"),
  strip: $("strip"), cards: $("cards"), empty: $("cards-empty"), chips: $("attacks"), honest: $("honest"),
  claude: $("brain-claude"), hijacked: $("brain-hijacked"),
};

let state = null;
let timer = null;
let signature = "";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showProblem(message) {
  els.problem.textContent = message || "";
  els.problem.hidden = !message;
}

async function refresh() {
  clearTimeout(timer);
  let response;
  try {
    response = await fetch("/api/console", { credentials: "same-origin" });
  } catch (_) {
    showProblem("Cannot reach the demo service.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  if (response.status === 401) {   // the chat is still signing in
    timer = setTimeout(refresh, 1500);
    return;
  }
  if (!response.ok) {
    showProblem(response.status === 503 ? "The database does not answer. Is the stack running?" : "Something went wrong.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  showProblem("");
  const body = await response.json();
  const text = JSON.stringify(body);
  if (text !== signature) {
    signature = text;
    state = body;
    render();
  }
  timer = setTimeout(refresh, state.cards.some((c) => c.badge.kind === "running") ? 1200 : 4000);
}

document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });

function render() {
  const s = state.summary;
  els.blocked.textContent = String(s.blocked);
  els.waiting.textContent = String(s.waiting);
  els.kill.textContent = s.killSwitch === "on" ? "on · agents paused" : "off · agents running";
  els.kill.className = "v " + (s.killSwitch === "on" ? "bad" : "ok");
  els.claude.textContent = "Brain: " + state.backend.name;
  renderChips();
  renderStrip();
  renderCards();
}

// ---- the brain switch ----

function setHijacked(on) {
  els.claude.setAttribute("aria-pressed", String(!on));
  els.hijacked.setAttribute("aria-pressed", String(on));
  els.chips.hidden = !on;
  els.honest.hidden = on;
}
els.claude.addEventListener("click", () => setHijacked(false));
els.hijacked.addEventListener("click", () => setHijacked(true));

// Clicking a chip sends its text with that attack, in one request.
function renderChips() {
  if (els.chips.childElementCount) return;
  for (const attack of state.attacks) {
    const chip = el("button", "chip", attack.typed);
    chip.type = "button";
    chip.addEventListener("click", () => window.volt.send(attack.typed, attack.id));
    els.chips.append(chip);
  }
}

// ---- the strip: the part that acted on the newest message lights up ----

function renderStrip() {
  const hit = state.cards.length ? state.cards[0].nodes : [];
  for (const item of els.strip.children) {
    const on = hit.includes(item.dataset.key);
    item.className = !on ? "" : item.dataset.key === "staff" ? "wait" : "hit";
  }
}

// ---- one card per message, newest first ----

function line(label, text) {
  const row = el("div");
  row.append(el("b", "", label), document.createTextNode(text));
  return row;
}

function renderCards() {
  els.empty.hidden = state.cards.length > 0;
  els.cards.replaceChildren();
  for (const c of state.cards) {
    const item = el("li", "glass wcard");
    item.append(
      line("The AI tried: ", c.tried),
      line("Stopped by: ", c.stopped),
      line("The customer got: ", c.got),
      el("span", "badge " + c.badge.kind, c.badge.text));
    els.cards.append(item);
  }
}

setHijacked(false);
refresh();
