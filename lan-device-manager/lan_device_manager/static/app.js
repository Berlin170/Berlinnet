"use strict";

/* LAN Device Manager - dashboard front end.
 *
 * Talks only to the local API on this machine. Everything shown here comes from
 * a real scan or a real router probe; nothing is mocked.
 */

const el = (id) => document.getElementById(id);

/* ================================================================== api === */

const api = {
  async get(path) {
    const response = await fetch(path);
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || response.statusText);
    }
    return response.json();
  },
  async send(method, path, body) {
    const response = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.detail || data.message || response.statusText);
      error.payload = data;
      throw error;
    }
    return data;
  },
};

/* ================================================================ state === */

const state = {
  devices: [],
  stats: {},
  overview: {},
  router: null,
  filter: "all",
  sort: "ip",
  sortDir: 1,
  query: "",
  // ?view=cards makes a particular layout linkable; otherwise the last choice sticks.
  view: new URLSearchParams(location.search).get("view")
        || localStorage.getItem("ldm.view") || "table",
  scanning: false,
  togglingMonitor: false,
  loaded: false,
};

/* ================================================================ icons === */

const svg = (paths, extra = "") =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"
        stroke-linecap="round" stroke-linejoin="round" ${extra}>${paths}</svg>`;

const ICONS = {
  router: svg(`<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01"/><path d="M12 9V3M8.5 6.5 12 3l3.5 3.5"/>`),
  computer: svg(`<rect x="2.5" y="4" width="19" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>`),
  phone: svg(`<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M11 18.5h2"/>`),
  tv: svg(`<rect x="2.5" y="4" width="19" height="12.5" rx="2"/><path d="M8 20.5h8"/>`),
  printer: svg(`<path d="M6.5 9V3.5h11V9"/><rect x="2.5" y="9" width="19" height="7" rx="2"/><path d="M6.5 14h11v6.5h-11z"/>`),
  nas: svg(`<rect x="2.5" y="3.5" width="19" height="7" rx="2"/><rect x="2.5" y="13.5" width="19" height="7" rx="2"/><path d="M6.5 7h.01M6.5 17h.01"/>`),
  iot: svg(`<path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/><circle cx="12" cy="12" r="3.5"/>`),
  camera: svg(`<path d="M2.5 8.5a2 2 0 0 1 2-2h2l1.5-2h6l1.5 2h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/><circle cx="12" cy="13" r="3.5"/>`),
  console: svg(`<rect x="2" y="7" width="20" height="10" rx="4"/><path d="M7 10.5v3M5.5 12h3M16 11h.01M18 13.5h.01"/>`),
  vm: svg(`<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M9 9.5 11.5 12 9 14.5M13 14.5h3M8 20.5h8"/>`),
  unknown: svg(`<circle cx="12" cy="12" r="9"/><path d="M9.5 9.2a2.6 2.6 0 0 1 5 .9c0 1.7-2.5 2.1-2.5 3.6"/><path d="M12 17.2h.01"/>`),
};

const CATEGORY_ICON = {
  "Router / Gateway": "router",
  "Computer": "computer",
  "Phone / Tablet": "phone",
  "TV / Streaming": "tv",
  "Printer": "printer",
  "NAS / Server": "nas",
  "IoT / Smart home": "iot",
  "Camera": "camera",
  "Games console": "console",
  "Virtual machine": "vm",
  "Unknown": "unknown",
};

const UI = {
  check: svg(`<circle cx="12" cy="12" r="9"/><path d="m8.5 12.2 2.3 2.3 4.7-4.7"/>`),
  warn: svg(`<path d="M12 4.5 21 19.5H3z"/><path d="M12 10v4M12 17h.01"/>`),
  error: svg(`<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>`),
  info: svg(`<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>`),
  radar: svg(`<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18 7"/>`),
  sun: svg(`<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.2 5.2l1.4 1.4M17.4 17.4l1.4 1.4M18.8 5.2l-1.4 1.4M6.6 17.4l-1.4 1.4"/>`),
  moon: svg(`<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5"/>`),
  shield: svg(`<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.2-7.5 9.5-4.4-1.3-7.5-4.9-7.5-9.5V6z"/>`),
  lock: svg(`<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>`),
  wifi: svg(`<path d="M5 12.5a10 10 0 0 1 14 0M2 8.8a15 15 0 0 1 20 0M8.5 16.2a5 5 0 0 1 7 0"/><circle cx="12" cy="20" r="1.1" fill="currentColor"/>`),
  cable: svg(`<path d="M7 3v5M17 3v5M5.5 8h13v4a6.5 6.5 0 0 1-13 0z"/><path d="M12 18.5V22"/>`),
};

/* ============================================================== helpers === */

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function timeAgo(seconds) {
  if (!seconds) return "never";
  const delta = Date.now() / 1000 - seconds;
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

const fullTime = (seconds) => (seconds ? new Date(seconds * 1000).toLocaleString() : "-");

const ipSortKey = (ip) =>
  (ip || "").split(".").reduce((acc, part) => acc * 256 + (parseInt(part, 10) || 0), 0);

/** Long vendor strings crowd the table, so trim the corporate suffixes. */
function shortVendor(vendor) {
  if (!vendor) return "Unknown";
  if (vendor.startsWith("Randomised")) return "Randomised";
  return vendor
    .replace(/\b(Inc|Corp|Corporation|Co|Ltd|LLC|GmbH|Technologies|Technology|Company|Limited)\b\.?/gi, "")
    .replace(/[,.]\s*$/, "")
    .trim() || vendor;
}

function iconFor(device) {
  if (device.is_gateway) return ICONS.router;
  return ICONS[CATEGORY_ICON[device.category] || "unknown"];
}

function toast(message, kind = "info", title = "") {
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.innerHTML = `${UI[kind] || UI.info}<div>${
    title ? `<div class="title">${escapeHtml(title)}</div>` : ""
  }<div class="body">${escapeHtml(message)}</div></div>`;
  el("toasts").appendChild(node);
  setTimeout(() => {
    node.style.transition = "opacity .3s, transform .3s";
    node.style.opacity = "0";
    node.style.transform = "translateX(16px)";
    setTimeout(() => node.remove(), 320);
  }, kind === "error" ? 9000 : 6000);
}

/* ================================================================ theme === */

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", mode);
  localStorage.setItem("ldm.theme", mode);

  const dark = mode === "dark" ||
    (mode === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  el("themeBtn").innerHTML = dark ? UI.sun : UI.moon;
  el("themeBtn").title = `Theme: ${mode} — click to change`;
}

function cycleTheme() {
  const order = ["system", "light", "dark"];
  const current = localStorage.getItem("ldm.theme") || "system";
  applyTheme(order[(order.indexOf(current) + 1) % order.length]);
}

/* ============================================================ rendering === */

function renderNetwork() {
  const iface = state.overview.interface;
  const chips = el("netChips");
  if (!iface) {
    chips.innerHTML = `<span class="netchip"><b>Network</b><span>no active interface</span></span>`;
    return;
  }
  const facts = [
    ["Adapter", iface.name],
    ["This PC", iface.ipv4],
    ["Subnet", iface.cidr],
    ["Gateway", iface.gateway || "none"],
  ];
  chips.innerHTML = facts
    .map(([k, v]) => `<span class="netchip"><b>${escapeHtml(k)}</b><span>${escapeHtml(v)}</span></span>`)
    .join("");
}

const STAT_CARDS = [
  { key: "online", label: "Online", tone: "green", filter: "online",
    icon: svg(`<path d="M5 12.5a10 10 0 0 1 14 0M2 8.8a15 15 0 0 1 20 0M8.5 16.2a5 5 0 0 1 7 0"/><circle cx="12" cy="20" r="1.1" fill="currentColor"/>`) },
  { key: "offline", label: "Offline", tone: "off", filter: "offline",
    icon: svg(`<path d="M3 3l18 18"/><path d="M8.5 16.2a5 5 0 0 1 6-.8M5 12.5a10 10 0 0 1 6-2.4M2 8.8a15 15 0 0 1 8-3.6"/><circle cx="12" cy="20" r="1.1" fill="currentColor"/>`) },
  { key: "unknown", label: "Unknown", tone: "amber", filter: "unknown",
    icon: svg(`<circle cx="12" cy="12" r="9"/><path d="M9.5 9.2a2.6 2.6 0 0 1 5 .9c0 1.7-2.5 2.1-2.5 3.6M12 17.2h.01"/>`) },
  { key: "new", label: "New", tone: "accent", filter: "new",
    icon: svg(`<path d="M12 4v16M4 12h16"/>`) },
  { key: "wireless", label: "On Wi-Fi", tone: "amber", filter: "wireless",
    icon: svg(`<path d="M5 12.5a10 10 0 0 1 14 0M2 8.8a15 15 0 0 1 20 0M8.5 16.2a5 5 0 0 1 7 0"/><circle cx="12" cy="20" r="1.1" fill="currentColor"/>`) },
  { key: "blocked", label: "Blocked", tone: "red", filter: "blocked",
    icon: svg(`<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>`) },
  { key: "total", label: "Total", tone: "violet", filter: "all",
    icon: svg(`<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7.5h.01M7 17h.01"/>`) },
];

// Each tile carries its own colour plus a matching wash for the icon chip.
const TONE = {
  green:  ["var(--green)", "var(--green-wash)"],
  amber:  ["var(--amber)", "var(--amber-wash)"],
  red:    ["var(--red)", "var(--red-wash)"],
  violet: ["var(--violet)", "var(--violet-wash)"],
  accent: ["var(--accent)", "var(--accent-wash)"],
  off:    ["var(--text-3)", "var(--surface-2)"],
};

function renderStats() {
  el("stats").innerHTML = STAT_CARDS.map((card) => {
    const [tone, wash] = TONE[card.tone];
    const active = state.filter !== "all" && state.filter === card.filter;
    return `
    <button class="stat ${active ? "active" : ""}"
            style="--tone:${tone};--tone-wash:${wash}" data-filter="${card.filter}">
      <span class="stat-icon">${card.icon}</span>
      <span class="stat-text">
        <span class="n">${state.stats[card.key] ?? 0}</span>
        <span class="k">${card.label}</span>
      </span>
    </button>`;
  }).join("");

  el("stats").querySelectorAll(".stat").forEach((node) => {
    node.onclick = () => {
      // Clicking the active card clears the filter, which is what people expect.
      state.filter = state.filter === node.dataset.filter ? "all" : node.dataset.filter;
      el("filter").value = state.filter;
      renderStats();
      renderDevices();
    };
  });
}

function renderRouter() {
  const info = state.router && state.router.router;
  const caps = state.router && state.router.capabilities;

  if (!info) {
    el("routerTitle").textContent = "No router detected";
    el("routerSub").textContent = "This interface has no gateway.";
    el("routerDetail").innerHTML = "";
    return;
  }

  const name = [info.vendor, info.model].filter(Boolean).join(" ") || "Unknown router";
  const authed = caps && caps.auth_state === "authenticated";

  el("routerTitle").innerHTML =
    `${escapeHtml(name)}` +
    (caps
      ? caps.can_block
        ? ` <span class="pill trusted">Blocking available</span>`
        : ` <span class="pill unknown">Blocking unavailable</span>`
      : "") +
    (authed ? ` <span class="pill">Signed in</span>` : "");

  el("routerSub").textContent =
    `${info.ip} · ${info.http_server || "no web server"} · detected with ${info.confidence} confidence`;

  const facts = [
    ["Gateway IP", info.ip],
    ["MAC", info.mac || "unknown"],
    ["Manufacturer", info.vendor || "unknown"],
    ["Model", info.model || "not advertised"],
    ["Web server", info.http_server || "none"],
    ["Open ports", (info.open_ports || []).join(", ") || "none"],
    ["Adapter", state.router.adapter.name],
  ];

  let html = `<div class="kv">` + facts.map(([k, v]) => `
    <div><div class="label">${escapeHtml(k)}</div><div class="value">${escapeHtml(v)}</div></div>
  `).join("") + `</div>`;

  if (caps) {
    if (caps.can_block) {
      html += `<div class="notice ok"><strong>Blocking is available</strong>
        This router exposes a supported mechanism (${escapeHtml(caps.method.replace(/_/g, " "))}),
        so Block and Unblock make a real change on the router.</div>`;
    } else {
      html += `<div class="notice warn"><strong>Blocking is not available</strong>
        ${escapeHtml(caps.unsupported_reason)}`;
      if (caps.alternatives && caps.alternatives.length) {
        html += `<ul>` + caps.alternatives.map((a) => `<li>${escapeHtml(a)}</li>`).join("") + `</ul>`;
      }
      html += `</div>`;
    }
    if (caps.probed && caps.probed.length) {
      html += `<details class="probe"><summary>What was checked</summary><pre>${
        caps.probed.map(escapeHtml).join("\n")}</pre></details>`;
    }
  }

  if (info.evidence && info.evidence.length) {
    html += `<details class="probe"><summary>How the router was identified</summary><pre>${
      info.evidence.map(escapeHtml).join("\n")}</pre></details>`;
  }

  html += `<div class="modal-actions" style="justify-content:flex-start">
      <button class="btn sm" id="routerAuthBtn">${authed ? "Disconnect" : "Connect"}</button>
      ${state.router.adapter.name === "huawei" ?
        `<a class="btn sm subtle" id="routerMacFilterBtn" href="http://${escapeHtml(info.ip)}/cgi-bin/sec-macfilter.asp" target="_blank" rel="noopener">Open MAC Filter</a>` : ""}
      <button class="btn sm subtle" id="routerRefreshBtn">Re-detect</button>
    </div>`;

  el("routerDetail").innerHTML = html;
  el("routerAuthBtn").onclick = authed ? doRouterLogout : openLoginModal;
  el("routerRefreshBtn").onclick = redetectRouter;
}

/* --------------------------------------------------------- device lists -- */

function matchesFilter(device) {
  switch (state.filter) {
    case "online": return device.online;
    case "offline": return !device.online;
    case "new": return device.is_new;
    case "unknown": return device.trust === "unknown";
    case "trusted": return device.trust === "trusted";
    case "blocked": return device.blocked;
    case "wireless": return device.link_type === "wireless";
    case "wired": return device.link_type === "wired";
    default: return true;
  }
}

function matchesQuery(device) {
  if (!state.query) return true;
  return [device.display_name, device.custom_name, device.hostname, device.ip,
          device.mac, device.vendor, device.category, device.notes]
    .filter(Boolean).join(" ").toLowerCase().includes(state.query);
}

function visibleDevices() {
  const list = state.devices.filter((d) => matchesFilter(d) && matchesQuery(d));
  const dir = state.sortDir;
  const by = {
    name: (a, b) => a.display_name.localeCompare(b.display_name),
    ip: (a, b) => ipSortKey(a.ip) - ipSortKey(b.ip),
    seen: (a, b) => (a.last_seen || 0) - (b.last_seen || 0),
  }[state.sort] || ((a, b) => ipSortKey(a.ip) - ipSortKey(b.ip));
  return list.sort((a, b) => by(a, b) * dir);
}

const blockingAvailable = () => !!(state.router && state.router.capabilities
                                   && state.router.capabilities.can_block);

const NO_BLOCK_TOOLTIP = "Router does not expose a supported blocking method.";

/** Wi-Fi vs cable is the useful split when freeloaders are all wireless. */
function linkBadge(device) {
  if (device.link_type === "wireless") {
    return `<span class="pill wifi" title="${escapeHtml(device.link_reason || "")}">${UI.wifi}Wi-Fi</span>`;
  }
  if (device.link_type === "wired") {
    return `<span class="pill wired" title="${escapeHtml(device.link_reason || "")}">${UI.cable}Wired</span>`;
  }
  return "";
}

function badgesFor(device) {
  const out = [];
  const link = linkBadge(device);
  if (link) out.push(link);
  if (device.is_new) out.push(`<span class="pill new">New</span>`);
  if (device.blocked) out.push(`<span class="pill blocked">Blocked</span>`);
  if (device.trust === "trusted") out.push(`<span class="pill trusted">Trusted</span>`);
  if (device.is_gateway) out.push(`<span class="pill router">Router</span>`);
  if (device.is_self) out.push(`<span class="pill">This PC</span>`);
  return out.join(" ");
}

function actionsFor(device) {
  const protectedDevice = device.is_self || device.is_gateway;
  const disabled = !blockingAvailable() || protectedDevice;
  const title = protectedDevice
    ? "This app will not block the router or the computer it runs on."
    : (blockingAvailable() ? "Block this device at the router" : NO_BLOCK_TOOLTIP);
  const key = escapeHtml(device.key);

  const blockBtn = device.blocked
    ? `<button class="btn sm" data-act="unblock" data-key="${key}" ${disabled ? "disabled" : ""}
         title="${escapeHtml(title)}">Unblock</button>`
    : `<button class="btn sm danger" data-act="block" data-key="${key}" ${disabled ? "disabled" : ""}
         title="${escapeHtml(title)}">Block</button>`;

  return `<div class="actions">
      <button class="btn sm subtle" data-act="details" data-key="${key}">Details</button>
      <button class="btn sm" data-act="trust" data-key="${key}">${
        device.trust === "trusted" ? "Untrust" : "Trust"}</button>
      ${blockBtn}
    </div>`;
}

function avatarFor(device) {
  const tone = device.is_gateway ? "is-router" : device.is_self ? "is-self"
             : device.is_new ? "is-new" : "";
  return `<span class="avatar ${tone}">${iconFor(device)}</span>`;
}

function statusFor(device) {
  return `<div class="status">
      <span class="beacon ${device.online ? "on" : "off"}"></span>${device.online ? "Online" : "Offline"}
    </div><div class="seen">seen ${escapeHtml(timeAgo(device.last_seen))}</div>`;
}

function rowClass(device) {
  return device.blocked ? "flag-block" : device.is_new ? "flag-new" : "";
}

function renderTable(list) {
  el("deviceRows").innerHTML = list.map((device) => `
    <tr class="${rowClass(device)}">
      <td>
        <div class="device">
          ${avatarFor(device)}
          <div class="device-text">
            <div class="device-name">${escapeHtml(device.display_name)} ${badgesFor(device)}</div>
            <div class="device-sub">${escapeHtml(device.hostname || device.category || "")}</div>
          </div>
        </div>
      </td>
      <td data-label="IP"><span class="data mono">${escapeHtml(device.ip || "-")}</span></td>
      <td data-label="MAC"><span class="data mono">${escapeHtml(device.mac || "-")}</span></td>
      <td data-label="Vendor">${escapeHtml(shortVendor(device.vendor))}</td>
      <td data-label="Type">${escapeHtml(device.category || "Unknown")}</td>
      <td data-label="Status">${statusFor(device)}</td>
      <td>${actionsFor(device)}</td>
    </tr>`).join("");
}

function renderCards(list) {
  el("cardGrid").innerHTML = list.map((device) => `
    <article class="dcard ${rowClass(device)}">
      <div class="dcard-top">
        ${avatarFor(device)}
        <div class="device-text">
          <div class="device-name">${escapeHtml(device.display_name)}</div>
          <div class="device-sub">${escapeHtml(device.category || "Unknown")}</div>
        </div>
      </div>
      <div class="dcard-badges">${badgesFor(device) ||
        `<span class="pill">${device.online ? "Online" : "Offline"}</span>`}</div>
      <dl class="dcard-meta">
        <dt>IP</dt><dd class="mono">${escapeHtml(device.ip || "-")}</dd>
        <dt>MAC</dt><dd class="mono">${escapeHtml(device.mac || "-")}</dd>
        <dt>Vendor</dt><dd>${escapeHtml(shortVendor(device.vendor))}</dd>
        <dt>Status</dt><dd>${device.online
          ? `<span class="status"><span class="beacon on"></span>Online</span>`
          : `Seen ${escapeHtml(timeAgo(device.last_seen))}`}</dd>
      </dl>
      ${actionsFor(device)}
    </article>`).join("");
}

function emptyStateHtml() {
  if (!state.loaded) {
    return Array.from({ length: 4 }, () => `
      <div class="skeleton-row">
        <div class="sk av"></div>
        <div style="flex:1"><div class="sk l1"></div><div class="sk l2" style="margin-top:7px"></div></div>
      </div>`).join("");
  }
  const filtered = state.devices.length > 0;
  return `<div class="empty">${UI.radar}
      <h3>${filtered ? "Nothing matches those filters" : "No devices discovered yet"}</h3>
      <p>${filtered
        ? "Try clearing the search or switching back to All devices."
        : "Run a scan to see what is on your network."}</p>
    </div>`;
}

function renderDevices() {
  const list = visibleDevices();
  const empty = list.length === 0;

  el("tablePanel").hidden = state.view !== "table";
  el("cardGrid").hidden = state.view !== "cards" || empty;

  if (empty) {
    el("deviceRows").innerHTML = "";
    el("cardGrid").innerHTML = "";
    el("tablePanel").hidden = false;
    el("tableEmpty").innerHTML = emptyStateHtml();
    return;
  }

  el("tableEmpty").innerHTML = "";
  if (state.view === "table") renderTable(list);
  else renderCards(list);

  document.querySelectorAll("button[data-act]").forEach((button) => {
    button.onclick = () => handleAction(button.dataset.act, button.dataset.key);
  });

  document.querySelectorAll("th.sortable").forEach((th) => {
    const active = th.dataset.sort === state.sort;
    th.classList.toggle("sorted", active);
    const arrow = th.querySelector(".arrow");
    if (arrow) arrow.textContent = active && state.sortDir < 0 ? "▲" : "▼";
  });
}

/* ============================================================== actions === */

async function handleAction(action, key) {
  const device = state.devices.find((d) => d.key === key);
  if (!device) return;

  if (action === "details") return openDrawer(device);

  if (action === "trust") {
    const trust = device.trust === "trusted" ? "unknown" : "trusted";
    await api.send("PATCH", `/api/devices/${encodeURIComponent(key)}`,
                   { trust, acknowledged: true });
    toast(`${device.display_name} marked ${trust}.`, "ok");
    return refreshDevices();
  }

  if (action === "block" || action === "unblock") {
    try {
      const result = await api.send("POST", `/api/devices/${encodeURIComponent(key)}/${action}`);
      toast(result.message, result.ok ? "ok" : "warn", result.ok ? "Done" : "Not applied");
    } catch (error) {
      toast((error.payload && error.payload.message) || error.message, "error",
            "Blocking unavailable");
    }
    await refreshDevices();
    await refreshRouter();
  }
}

/* =============================================================== drawer === */

async function openDrawer(device) {
  el("drawerAvatar").innerHTML = iconFor(device);
  el("drawerTitle").textContent = device.display_name;
  el("drawerSub").textContent = `${device.ip || ""} · ${device.category || ""}`;
  el("drawerBody").innerHTML = `<div class="empty">Loading history…</div>`;
  el("drawer").classList.add("open");
  el("drawer").setAttribute("aria-hidden", "false");
  el("scrim").classList.add("open");

  let payload;
  try {
    payload = await api.get(`/api/devices/${encodeURIComponent(device.key)}/history`);
  } catch (error) {
    el("drawerBody").innerHTML = `<div class="empty"><p>${escapeHtml(error.message)}</p></div>`;
    return;
  }

  const record = payload.device;
  const events = payload.events || [];

  const facts = [
    ["IP address", record.ip],
    ["MAC address", record.mac || "not discovered"],
    ["Hostname", record.hostname ? `${record.hostname} (via ${record.hostname_source})` : "not resolved"],
    ["Vendor", record.vendor],
    ["Type", `${record.category} — ${record.category_confidence} confidence`],
    ["Why", record.category_reason],
    ["Connection", record.link_type === "wireless" ? `Wi-Fi — ${record.link_reason}`
                    : record.link_type === "wired" ? `Wired — ${record.link_reason}`
                    : "could not be determined"],
    ["Open ports", (record.open_ports || []).join(", ") || "none found"],
    ["Found via", (record.responded_to || []).join(", ")],
    ["First seen", fullTime(record.first_seen)],
    ["Last seen", fullTime(record.last_seen)],
    ["Times seen", record.times_seen],
  ];

  el("drawerBody").innerHTML = `
    <div class="section-title">Identification</div>
    <dl class="facts">${facts.map(([k, v]) =>
      `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v ?? "-")}</dd>`).join("")}</dl>

    <div class="section-title">Your labels</div>
    <div class="field">
      <label for="editName">Custom name</label>
      <input id="editName" value="${escapeHtml(record.custom_name || "")}" placeholder="e.g. Kitchen tablet">
    </div>
    <div class="field">
      <label for="editTrust">Trust</label>
      <select id="editTrust">
        <option value="unknown"${record.trust !== "trusted" ? " selected" : ""}>Unknown</option>
        <option value="trusted"${record.trust === "trusted" ? " selected" : ""}>Trusted</option>
      </select>
      ${record.blocked
        ? `<p class="hint">Blocked on the router (${escapeHtml((record.block_method || "").replace(/_/g, " "))}). Use Unblock to lift it.</p>`
        : `<p class="hint">Blocked is not a state you set by hand — it is only recorded when the router confirms a block.</p>`}
    </div>
    <div class="field">
      <label for="editNotes">Notes</label>
      <textarea id="editNotes" placeholder="Anything worth remembering about this device">${escapeHtml(record.notes || "")}</textarea>
    </div>
    <div style="display:flex;gap:9px">
      <button class="btn primary" id="saveDevice">Save</button>
      <button class="btn danger" id="forgetDevice">Forget</button>
    </div>

    <div class="section-title">History</div>
    <ul class="timeline">${events.length
      ? events.map((event) => `<li><div class="msg">${escapeHtml(event.message)}</div>
          <div class="at">${escapeHtml(fullTime(event.at))}</div></li>`).join("")
      : `<li><div class="at">No recorded events yet.</div></li>`}</ul>
  `;

  el("saveDevice").onclick = async () => {
    await api.send("PATCH", `/api/devices/${encodeURIComponent(record.key)}`, {
      custom_name: el("editName").value.trim(),
      notes: el("editNotes").value,
      trust: el("editTrust").value,
      acknowledged: true,
    });
    toast("Device saved.", "ok");
    closeDrawer();
    refreshDevices();
  };

  el("forgetDevice").onclick = async () => {
    await api.send("DELETE", `/api/devices/${encodeURIComponent(record.key)}`);
    toast("Device removed from the database.", "ok");
    closeDrawer();
    refreshDevices();
  };
}

function closeDrawer() {
  el("drawer").classList.remove("open");
  el("drawer").setAttribute("aria-hidden", "true");
  el("scrim").classList.remove("open");
}

/* ========================================================== router auth === */

function openLoginModal() {
  const info = state.router && state.router.router;
  el("loginSub").textContent = info
    ? `Sign in to ${info.model || info.vendor || "the router"} at ${info.ip}. Use the account printed on the router label or supplied by your ISP.`
    : "Sign in to the router on this network.";
  const canStore = state.router && state.router.can_store_credentials;
  el("loginRemember").disabled = !canStore;
  el("rememberLabel").textContent = canStore
    ? "Remember on this PC (encrypted with your Windows account)"
    : "Secure storage is unavailable on this system";
  el("loginModal").classList.add("open");
  el("loginUser").focus();
}

function closeLoginModal() {
  el("loginModal").classList.remove("open");
  el("loginForm").reset();
}

async function doRouterLogout() {
  await api.send("POST", "/api/router/logout");
  toast("Disconnected from the router.", "ok");
  await refreshRouter();
}

async function redetectRouter() {
  el("routerSub").textContent = "Re-detecting…";
  await api.send("POST", "/api/router/refresh").catch(() => {});
  await refreshRouter();
  toast("Router re-detected.", "ok");
}

/* ============================================================= scanning === */

async function doScan() {
  if (state.scanning) return;
  state.scanning = true;
  el("scanBtn").disabled = true;
  el("scanBtnLabel").textContent = "Scanning…";
  el("scanBar").classList.add("active");
  el("scanFill").style.width = "0%";

  const poll = setInterval(pollScanProgress, 600);
  try {
    const result = await api.send("POST", "/api/scan");
    toast(`${result.found} devices responded${result.new ? `, ${result.new} new` : ""}.`,
          "ok", "Scan complete");
  } catch (error) {
    toast(error.message, "error", "Scan failed");
  } finally {
    clearInterval(poll);
    state.scanning = false;
    el("scanBtn").disabled = false;
    el("scanBtnLabel").textContent = "Scan Network";
    el("scanBar").classList.remove("active");
    await refreshAll();
  }
}

async function pollScanProgress() {
  try {
    const status = await api.get("/api/scan/status");
    if (!status.running) return;
    el("scanFill").style.width = `${status.percent}%`;
    el("scanPhase").textContent = status.phase;
    el("scanCount").textContent = status.total ? `${status.done}/${status.total}` : "";
  } catch { /* the API is busy mid-scan; ignore */ }
}

async function checkNotifications() {
  try {
    const { notifications } = await api.get("/api/notifications");
    notifications.forEach((note) => {
      toast(note.message, note.kind === "new_device" ? "warn" : "info",
            note.kind === "new_device" ? "New device" : "");
    });
    if (notifications.length) await refreshDevices();
  } catch { /* transient */ }
}

/* ============================================================== loading === */

async function refreshDevices() {
  const data = await api.get("/api/devices");
  state.devices = data.devices;
  state.stats = data.stats;
  state.loaded = true;
  renderStats();
  renderDevices();
}

async function refreshRouter() {
  try {
    state.router = await api.get("/api/router");
  } catch {
    state.router = null;
  }
  renderRouter();
  renderDevices();
}

async function refreshOverview() {
  state.overview = await api.get("/api/overview");
  renderNetwork();
  const on = state.overview.monitoring;
  if (!state.togglingMonitor) {
    el("monitorBtn").classList.toggle("primary", on);
    el("monitorBtn").classList.toggle("subtle", !on);
  }
  el("monitorLabel").textContent = on
    ? `Auto ${Math.round(state.overview.interval / 60)}m`
    : "Auto-scan";
}

async function refreshAll() {
  await Promise.allSettled([refreshOverview(), refreshDevices(), refreshRouter()]);
}

/* =============================================================== wiring === */

applyTheme(localStorage.getItem("ldm.theme") || "system");
el("themeBtn").onclick = cycleTheme;
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  applyTheme(localStorage.getItem("ldm.theme") || "system");
});

el("scanBtn").onclick = doScan;
el("routerStrip").onclick = () => {
  const card = el("routerCard");
  const open = card.classList.toggle("open");
  el("routerStrip").setAttribute("aria-expanded", String(open));
};

el("search").oninput = (event) => {
  state.query = event.target.value.trim().toLowerCase();
  renderDevices();
};
el("filter").onchange = (event) => {
  state.filter = event.target.value;
  renderStats();
  renderDevices();
};
el("ackBtn").onclick = async () => {
  await api.send("POST", "/api/devices/acknowledge-all");
  await refreshDevices();
};

function setView(view) {
  state.view = view;
  localStorage.setItem("ldm.view", view);
  el("viewTable").classList.toggle("on", view === "table");
  el("viewCards").classList.toggle("on", view === "cards");
  renderDevices();
}
el("viewTable").onclick = () => setView("table");
el("viewCards").onclick = () => setView("cards");
setView(state.view);

document.querySelectorAll("th.sortable").forEach((th) => {
  th.onclick = () => {
    const column = th.dataset.sort;
    state.sortDir = state.sort === column ? -state.sortDir : 1;
    state.sort = column;
    renderDevices();
  };
});

el("monitorBtn").onclick = async () => {
  const wanted = !state.overview.monitoring;
  state.togglingMonitor = true;
  try {
    await api.send("POST", wanted ? "/api/monitor/start" : "/api/monitor/stop");
  } catch (error) {
    toast(error.message, "error", "Could not change auto-scan");
  } finally {
    state.togglingMonitor = false;
  }
  await refreshOverview();
};

el("drawerClose").onclick = closeDrawer;
el("scrim").onclick = closeDrawer;
el("loginCancel").onclick = closeLoginModal;
el("loginModal").onclick = (event) => {
  if (event.target === el("loginModal")) closeLoginModal();
};

el("loginForm").onsubmit = async (event) => {
  event.preventDefault();
  const submit = el("loginSubmit");
  submit.disabled = true;
  submit.textContent = "Connecting…";
  try {
    const result = await api.send("POST", "/api/router/login", {
      username: el("loginUser").value,
      password: el("loginPass").value,
      remember: el("loginRemember").checked,
    });
    toast(result.message, "ok", "Connected");
    closeLoginModal();
    await refreshRouter();
  } catch (error) {
    toast((error.payload && error.payload.message) || error.message, "error", "Sign-in failed");
  } finally {
    submit.disabled = false;
    submit.textContent = "Connect";
    el("loginPass").value = "";
  }
};

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") { closeDrawer(); closeLoginModal(); return; }
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (typing) return;
  if (event.key === "/") { event.preventDefault(); el("search").focus(); }
  if (event.key === "s") doScan();
  if (event.key === "t") cycleTheme();
});

/* ============================================================ lifecycle === */

renderDevices();          // paint skeletons immediately
refreshAll().then(() => {
  if (!state.devices.length) doScan();
});

setInterval(checkNotifications, 5000);
setInterval(refreshOverview, 15000);
setInterval(() => { if (!state.scanning) refreshDevices(); }, 20000);
