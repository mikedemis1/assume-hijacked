"use strict";

// The security console. Read-only apart from one control: which attack the next customer message
// carries. Everything is put on the page with textContent, never as HTML. The server sends only
// names it knows (tools, arguments) and fixed words; this file adds nothing from the records.

const $ = (id) => document.getElementById(id);
const els = {
  problem: $("problem"), who: $("who"), blocked: $("c-blocked"), waiting: $("c-waiting"),
  kill: $("c-kill"), needed: $("signin-needed"), board: $("board"), picks: $("picks"), note: $("p-note"),
  pickerBox: $("picker-box"), tabs: $("tabs"), orderBox: $("order-box"), order: $("order"), orderTag: $("o-tag"),
  flow: $("flow"), flowTicket: $("f-ticket"), contained: $("contained"), feed: $("feed"), feedEmpty: $("feed-empty"),
};

const PROBLEMS = {
  database: "The database does not answer. Is the stack running?",
  csrf: "The page was out of date. Reload it and try again.",
  signin: "",
};

let state = null;
let csrf = "";
let timer = null;
let signature = "";
let selected = null;   // ticket id the visitor chose; null = the newest
const picks = new Map();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function time(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour12: false });
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

function showProblem(message) {
  els.problem.textContent = message || "";
  els.problem.hidden = !message;
}

async function refresh() {
  clearTimeout(timer);
  let result;
  try {
    result = await api("/api/console");
  } catch (_) {
    showProblem("Cannot reach the demo service.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  if (result.status === 401) {
    state = null;
    els.needed.hidden = false;
    els.board.hidden = true;
    showProblem("");
    timer = setTimeout(refresh, 4000);
    return;
  }
  if (!result.ok) {
    showProblem(PROBLEMS[result.body && result.body.error] || "Something went wrong.");
    timer = setTimeout(refresh, 5000);
    return;
  }
  showProblem("");
  const text = JSON.stringify(result.body);
  const changed = text !== signature;
  signature = text;
  state = result.body;
  csrf = state.csrf || "";
  if (changed) render();
  const busy = state.tickets.some((t) => !t.replied);
  timer = setTimeout(refresh, busy ? 1200 : 4000);
}

document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });

function current() {
  if (!state.tickets.length) return null;
  return state.tickets.find((t) => t.id === selected) || state.tickets[0];
}

function render() {
  els.needed.hidden = true;
  els.board.hidden = false;
  els.who.textContent = "customer: " + state.customer.name;
  const s = state.summary;
  els.blocked.textContent = String(s.blocked);
  els.waiting.textContent = String(s.waiting);
  els.kill.textContent = s.killSwitch === "on" ? "on \u00b7 agents paused" : "off \u00b7 agents running";
  els.kill.className = "v " + (s.killSwitch === "on" ? "bad" : "ok");
  renderPicks();
  const ticket = current();
  renderTabs(ticket);
  renderTicket(ticket);
  renderFeed(ticket);
}

// ---- the presenter control ----

function renderPicks() {
  if (!picks.size) {
    for (const attack of state.attacks) {
      const button = el("button", "pick", attack.label);
      button.type = "button";
      button.setAttribute("aria-pressed", "false");
      button.append(el("small", "", attack.asi.join(" ")));
      button.addEventListener("click", () => arm(attack.id));
      picks.set(attack.id, button);
      els.picks.append(button);
    }
  }
  for (const attack of state.attacks) {
    picks.get(attack.id).setAttribute("aria-pressed", String(state.armed === attack.id));
  }
  const armed = state.attacks.find((a) => a.id === state.armed);
  els.note.textContent = armed
    ? "Armed: “" + armed.label + "”. The next message from " + state.customer.name + " is filed with this order after their words. Once."
    : "Off. The next message gets the normal answer. Choose an attack to simulate a hijacked model.";
}

async function arm(id) {
  const next = state.armed === id ? null : id;
  const result = await api("/api/arm", { method: "POST", body: { attack: next } });
  if (!result.ok) { showProblem(PROBLEMS[result.body && result.body.error] || "Could not change that."); return; }
  showProblem("");
  await refresh();
}

// ---- one ticket ----

function renderTabs(ticket) {
  els.pickerBox.hidden = state.tickets.length < 2;
  els.tabs.replaceChildren();
  for (const t of state.tickets) {
    const tab = el("button", "tab", "#" + t.id);
    tab.type = "button";
    tab.setAttribute("aria-pressed", String(ticket !== null && t.id === ticket.id));
    tab.addEventListener("click", () => { selected = t.id; render(); });
    els.tabs.append(tab);
  }
}

function renderTicket(ticket) {
  els.flowTicket.textContent = ticket ? "ticket #" + ticket.id : "";
  els.orderBox.hidden = !(ticket && ticket.order);
  if (ticket && ticket.order) {
    els.order.replaceChildren();
    for (const line of ticket.order) els.order.append(el("div", line.startsWith("CALL") ? "call" : "say", line));
    els.orderTag.textContent = ticket.attack ? ticket.attack.label : "";
  }
  const nodes = ticket ? ticket.flow : [];
  const items = els.flow.querySelectorAll(".node");
  const links = els.flow.querySelectorAll(".link");
  items.forEach((item, i) => {
    const node = nodes.find((n) => n.key === item.dataset.key);
    const state_ = node ? node.state : "idle";
    item.className = "node s-" + state_;
    item.querySelector(".n-note").textContent = node ? node.note : "";
    item.querySelector(".n-state").textContent = ", " + state_ + (node && node.note ? "," : "");
    if (links[i]) {
      // a link takes the colour of the wall it leads into, so the path lights up as far as the work went
      const next = nodes.find((n) => n.key === items[i + 1].dataset.key);
      links[i].className = "link" + (next && next.state !== "idle" ? " s-" + next.state : "");
    }
  });
  const banner = ticket && ticket.banner;
  els.contained.hidden = !banner;
  if (banner) {
    els.contained.className = "banner-ok " + banner.kind;
    els.contained.textContent = banner.text;
  }
}

// ---- the live feed ----

const BADGE = { neutral: ["s-passed", "passed"], ok: ["s-ok", "ok"], warn: ["s-changed", "changed"], bad: ["s-stopped", "stopped"] };

function renderFeed(ticket) {
  const rows = [];
  for (const t of state.tickets) {
    let at = "";
    t.feed.forEach((line, i) => {
      if (line.at) at = line.at;
      if (i === 0) return;               // "Ticket filed" says nothing a decision does
      rows.push({ t, line, at, i });
    });
  }
  rows.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : b.i - a.i));
  els.feedEmpty.hidden = rows.length > 0;
  els.feed.replaceChildren();
  for (const { t, line, at } of rows.slice(0, 60)) {
    const [klass, word] = BADGE[line.tone] || BADGE.neutral;
    const item = el("li", "row" + (ticket && t.id === ticket.id ? " cur" : ""));
    item.append(el("span", "t", time(at)));
    const who = el("span", "who");
    who.append(el("span", "id", "#" + t.id + " "), el("span", "what", line.label || "ticket"));
    const txt = el("span", "txt", line.text);
    if (line.note) txt.append(el("small", "", line.note));
    item.append(who, txt, el("span", "badge " + klass, word));
    els.feed.append(item);
  }
}

refresh();
