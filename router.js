// ---------------------------------------------------------------------------
// Router adapter — Huawei / iLINK HG8xxx ONT (Boa 0.94 web UI)
//
// Blocking a device has to happen on the router; this panel can only ask it to.
// On the HG8547M that means driving its MAC-filter page the way a browser does:
//
//   1. GET  /cgi-bin/index2.asp   — pick up the session cookie and the login
//                                    "check code" the page generates in JS.
//   2. POST /cgi-bin/index2.asp   — sign in (credentials in the clear; that is
//                                    the firmware's design, no HTTPS listener).
//   3. Crawl /cgi-bin/content.asp — find the MAC-filter list page and its
//                                    "add" sub-page (sec_addmacfilter.asp).
//   4. POST the add form          — MAC + enable + the per-page X_HW_Token and
//                                    a self-generated check code.
//   5. Re-read the list page      — confirm the entry is actually there, so a
//                                    wrong field mapping reports failure rather
//                                    than a false success.
//
// The "check code" is NOT a server CAPTCHA: the login page builds it in the
// browser with getRandomLetterNum() / Math.random().toString(36) and only
// compares it client-side, so a code of the same shape (6 base-36 chars) is all
// the CGI needs to see. See the Python lan-device-manager for the same contract.
//
// Out of the box this is OFF and blocking is tracked in the panel only. To make
// it real, set enabled:true and fill in your username/password below.
//
// What this does NOT do: guess or brute-force passwords, exploit firmware bugs,
// deauth, or ARP-spoof. If the block cannot be confirmed it says so honestly.
// ---------------------------------------------------------------------------

const CONFIG = {
  enabled: false,

  baseUrl: 'http://192.168.1.1',
  // The ISP account, or superadmin if you have it. NOT the Wi-Fi password.
  username: 'telecomadmin',
  password: '',

  loginPath: '/cgi-bin/index2.asp',
  mainPath: '/cgi-bin/content.asp',

  // Whole exchange must finish well inside the panel's request.
  timeoutMs: 10000,
  maxCrawl: 40
};

function isConfigured() {
  return CONFIG.enabled && !!CONFIG.password;
}

// --------------------------------------------------------------- http + cookies

// A minimal cookie jar. The box keys the session on SESSIONID and also reads
// UID/PSW/LoginTimes cookies during login, so we set those ourselves.
function makeJar() {
  const jar = {};
  return {
    set(name, value) { jar[name] = value; },
    absorb(setCookies) {
      for (const line of setCookies || []) {
        const pair = line.split(';', 1)[0];
        const eq = pair.indexOf('=');
        if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    },
    header() {
      return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    },
    delete(name) { delete jar[name]; }
  };
}

function joinUrl(path) {
  if (/^https?:\/\//i.test(path)) return path;
  return CONFIG.baseUrl.replace(/\/+$/, '') + (path.startsWith('/') ? path : '/' + path);
}

function resolvePath(basePath, action) {
  if (!action) return basePath;
  if (action.startsWith('/')) return action;
  const dir = basePath.slice(0, basePath.lastIndexOf('/') + 1);
  return dir + action;
}

// The pages declare gb2312, but every field name, value and MAC we read is
// ASCII, so latin1 keeps those bytes intact without a decoder dependency.
async function httpGet(jar, path, referer) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
  try {
    // Feature pages 401 without a Referer pointing back at the frameset; the
    // login and menu assets do not care, so default it to content.asp.
    const res = await fetch(joinUrl(path), {
      headers: {
        Cookie: jar.header(),
        'User-Agent': 'NetPanel/1.0',
        Referer: joinUrl(referer || CONFIG.mainPath)
      },
      redirect: 'follow',
      signal: controller.signal
    });
    if (typeof res.headers.getSetCookie === 'function') jar.absorb(res.headers.getSetCookie());
    const buf = Buffer.from(await res.arrayBuffer());
    return { status: res.status, body: buf.toString('latin1') };
  } finally {
    clearTimeout(t);
  }
}

async function httpPost(jar, path, fields, referer) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
  try {
    const res = await fetch(joinUrl(path), {
      method: 'POST',
      headers: {
        Cookie: jar.header(),
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'NetPanel/1.0',
        Referer: joinUrl(referer || path)
      },
      body: new URLSearchParams(fields).toString(),
      redirect: 'follow',
      signal: controller.signal
    });
    if (typeof res.headers.getSetCookie === 'function') jar.absorb(res.headers.getSetCookie());
    const buf = Buffer.from(await res.arrayBuffer());
    return { status: res.status, body: buf.toString('latin1') };
  } finally {
    clearTimeout(t);
  }
}

// ------------------------------------------------------------------- html bits

const MAC_RE = /\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b/g;
const LINK_RE = /(?:src|href|location(?:\.href)?\s*=|url\s*:)\s*=?\s*["']([^"']*\.(?:asp|cgi))["']/gi;
const FORM_ACTION_RE = /<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/i;
const VALUE_RE = /\bvalue\s*=\s*["']([^"']*)["']/i;

// Verified HG8547M (Boa) MAC-filter contract — see the Python lan-device-manager
// huawei.py for the full write-up. Pages use HYPHENS; the list frame uses an
// underscore. The menu (real page URLs) lives in /JS/menu.js, and entries are
// emitted in JS as stMacFilter(domain, Name, MAC, Enable).
const MENU_JS = '/JS/menu.js';
const MACFILTER_PATH = '/cgi-bin/sec-macfilter.asp';
const MACFILTER_ADD_PATH = '/cgi-bin/sec-addmacfilter.asp';
const MACFILTER_LIST_CGI = '/cgi-bin/sec_macfilterlist.cgi';
const MENU_NODE_RE = /MenuNodeConstruction\s*\(\s*\d+\s*,\s*[^,]+,\s*["']([^"']+)["']/gi;
const ST_MACFILTER_RE = /stMacFilter\s*\(\s*(['"])(.*?)\1\s*,\s*(['"])(.*?)\3\s*,\s*(['"])(.*?)\5\s*,\s*(['"])(.*?)\7\s*\)/gis;

// Rows the list frame renders in JS: [{name, mac, enable}] in menu order, so a
// row's array index (needed by the delete form) is just its position here.
function listEntries(body) {
  const out = [];
  let m;
  ST_MACFILTER_RE.lastIndex = 0;
  while ((m = ST_MACFILTER_RE.exec(body)) !== null) {
    out.push({ name: m[4], mac: m[6].toLowerCase(), enable: m[8] });
  }
  return out;
}

// Feature-page URLs declared in the JS menu (content.asp holds only globals).
function menuPaths(body) {
  const out = [];
  let m;
  MENU_NODE_RE.lastIndex = 0;
  while ((m = MENU_NODE_RE.exec(body)) !== null) {
    if (!out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

function filterMode(body) {
  const m = body.match(/var\s+Mode\s*=\s*["'](Black|White)/i);
  return m ? (m[1][0].toUpperCase() + m[1].slice(1).toLowerCase()) : null;
}

// The login check code, rendered as an <input value> or <button>text</button>.
function loginChallenge(page) {
  const tag = page.match(/<(?:input|button)\b[^>]*\b(?:id|name)\s*=\s*["']GenRandom["'][^>]*>(?:\s*([^<\s]+)\s*<\/button>)?/i);
  if (!tag) return null;
  const val = tag[0].match(VALUE_RE);
  if (val) return val[1].trim();
  return tag[1] ? tag[1].trim() : null;
}

// Reproduce the router's own getRandomLetterNum(len): base-36, 0-9a-z.
function checkCode(len = 6) {
  const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
  let s = '';
  for (let i = 0; i < len; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
  return s;
}

// Reproduce createNewSessionID(): the client makes its own "boasid" + 8 hex id
// and cookies it before posting; the router validates the shape, not a value it
// issued (it never Set-Cookies one). Example: boasid3e0e965b.
function newSessionId() {
  let s = '';
  for (let i = 0; i < 8; i++) s += '0123456789abcdef'[Math.floor(Math.random() * 16)];
  return 'boasid' + s;
}

// Every <input>/<select> as { name, value, type, checked }.
function parseInputs(body) {
  const out = [];
  const tags = body.match(/<(?:input|select)\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const name = tag.match(/\bname\s*=\s*["']([^"']+)["']/i);
    if (!name) continue;
    const value = tag.match(VALUE_RE);
    const type = tag.match(/\btype\s*=\s*["']?([a-z]+)/i);
    out.push({
      name: name[1],
      value: value ? value[1] : '',
      type: type ? type[1].toLowerCase() : 'text',
      checked: /\bchecked\b/i.test(tag)
    });
  }
  return out;
}

function macsIn(body) {
  return (body.replace(/-/g, ':').match(MAC_RE) || []).map((m) => m.toLowerCase());
}

function macForPage(mac, body) {
  const canon = mac.trim().toLowerCase().replace(/-/g, ':');
  return /[0-9a-f]{2}-[0-9a-f]{2}/i.test(body) ? canon.replace(/:/g, '-') : canon;
}

const CHECKCODE_HINTS = ['random', 'checkcode', 'check_code', 'verifycode', 'vercode', 'captcha'];
const TOKEN_RE = /<input\b[^>]*\bname\s*=\s*["']((?:x\.)?(?:X_HW_Token|onttoken|csrf_?token))["'][^>]*>/i;

// ------------------------------------------------------------------------ login

async function login(jar) {
  const page = await httpGet(jar, CONFIG.loginPath);
  // The check code is generated in the browser (getRandomLetterNum), not by the
  // server, which never validates it — GenRandom ships empty and is only filled
  // on click. So generate our own and post it in both fields, as a real submit
  // would. Reading it off the page finds only the empty value.
  const code = loginChallenge(page.body) || checkCode();

  jar.set('SESSIONID', newSessionId());   // client-generated, as the page does
  jar.set('UID', CONFIG.username);
  jar.set('PSW', CONFIG.password);
  jar.set('LoginTimes', '1');

  const form = {
    Username: CONFIG.username,
    Password: CONFIG.password,
    Password1: CONFIG.password,
    Password2: CONFIG.password,
    Logoff: '0',
    hLoginTimes: '1',
    hLoginTimes_Zero: '0',
    value_one: '1',
    logintype: 'usr',
    Language_Flag: '0',
    GenRandom: code,
    RandomNumb: code
  };

  const res = await httpPost(jar, CONFIG.loginPath, form, CONFIG.loginPath);
  // NB: keep the PSW cookie — it IS the session on this box, so every
  // authenticated request must carry it. It lives only in this in-memory jar
  // and is dropped when setBlocked() returns. Deleting it here logged us
  // straight back out, so content.asp bounced to login and looked like a bad
  // password.

  // "already logged in" verdicts the page emits as userlogin(1|2).
  const logged = res.body.match(/userlogin\s*\(\s*(\d)\s*\)/);
  if (logged && (logged[1] === '1' || logged[1] === '2')) {
    return { ok: false, message: 'A session is already open on the router. Log out in the browser or wait for it to time out, then retry.' };
  }

  // Authoritative: the main frame is only served to a live session.
  const main = await httpGet(jar, CONFIG.mainPath);
  if (main.status !== 200 || /index2\.asp/i.test(main.body.slice(0, 400))) {
    return { ok: false, message: 'The router rejected those credentials. Check the username/password (the ISP account, not the Wi-Fi password).' };
  }
  return { ok: true, mainBody: main.body };
}

async function logout(jar) {
  // Single-session box: free the slot so the next login is not refused until
  // timeout. logout.cgi is what the UI's Log Out uses; Logoff=1 is the legacy path.
  try { await httpGet(jar, '/cgi-bin/logout.cgi', CONFIG.mainPath); } catch (e) { /* best effort */ }
  try { await httpGet(jar, CONFIG.loginPath + '?Logoff=1'); } catch (e) { /* best effort */ }
}

// --------------------------------------------------------------- page discovery

// Is the MAC-filter page present for this account? The real URL is named only in
// /JS/menu.js (content.asp holds globals), so we read the menu source.
async function hasMacFilter(jar) {
  const mj = await httpGet(jar, MENU_JS, CONFIG.mainPath);
  return mj.status === 200 && menuPaths(mj.body).includes(MACFILTER_PATH);
}

async function currentEntries(jar) {
  // The list CGI only emits its rows if its parent page was fetched first in the
  // same session; on its own it returns an empty table. Skipping this prime made
  // unblock see an empty list, conclude "nothing to remove", and report success
  // while the entry stayed.
  await httpGet(jar, MACFILTER_PATH, CONFIG.mainPath);
  const r = await httpGet(jar, MACFILTER_LIST_CGI, MACFILTER_PATH);
  return r.status === 200 ? listEntries(r.body) : [];
}

// The box commits a Save_Flag change a beat after answering, and its list frame
// reads back eventually-consistent, so poll until it reflects the write.
async function confirmPresence(jar, macCanon, wantPresent, tries = 4, delayMs = 800) {
  let present = (await currentEntries(jar)).some((e) => e.mac === macCanon);
  for (let i = 0; i < tries - 1 && present !== wantPresent; i++) {
    await new Promise((r) => setTimeout(r, delayMs));
    present = (await currentEntries(jar)).some((e) => e.mac === macCanon);
  }
  return present;
}

// ---------------------------------------------------------------- add / remove

async function atpAdd(jar, mac) {
  const macFmt = mac.trim().toUpperCase().replace(/-/g, ':');
  const tail = macFmt.replace(/:/g, '').slice(-6).toLowerCase();
  const payload = {
    Save_Flag: '1', EnableMac_Flag: 'Yes', curNum: '0', RuleType_Flag: 'MAC',
    Direction_Flag: 'Incoming', IpMacType_Flag: 'Mac', Actionflag: 'Add',
    Interface_Flag: 'br0', Selected_Menu: 'Security->MAC Filter',
    Name: 'blk' + tail, SourceMACAddress: macFmt, Enable: 'on'
  };
  const post = await httpPost(jar, MACFILTER_ADD_PATH, payload, MACFILTER_ADD_PATH);
  if (post.status !== 200) return { enforced: false, message: `Router returned HTTP ${post.status} on the add request.` };

  if (!(await confirmPresence(jar, macFmt.toLowerCase(), true))) {
    const modeBody = (await httpGet(jar, MACFILTER_PATH, CONFIG.mainPath)).body;
    const extra = filterMode(modeBody) === 'White'
      ? ' The filter is in Whitelist mode — switch it to Blacklist on the router for Block to deny.' : '';
    return { enforced: false, message: 'The router accepted the request but the device is not in its filter list afterwards, so the block did not take effect.' + extra };
  }
  const modeBody = (await httpGet(jar, MACFILTER_PATH, CONFIG.mainPath)).body;
  const warn = filterMode(modeBody) === 'White'
    ? ' Note: the filter is in Whitelist mode, so this entry ALLOWS the device — switch to Blacklist to deny it.' : '';
  return { enforced: true, message: 'Blocked on the router.' + warn };
}

async function atpRemove(jar, mac) {
  const canon = mac.trim().toLowerCase().replace(/-/g, ':');
  const entries = await currentEntries(jar);
  const index = entries.findIndex((e) => e.mac === canon);
  if (index < 0) return { enforced: true, message: `${mac} is not in the router's filter list.` };

  const modeBody = (await httpGet(jar, MACFILTER_PATH, CONFIG.mainPath)).body;
  const mode = filterMode(modeBody) || 'Black';
  const payload = {
    ListType_Flag: mode, Mac_Flag: '3', delnum: index + ',', EnMacFilter_Flag: '1',
    mac_num: String(entries.length), Actionflag: 'Del', IpMacType_Flag: 'Mac',
    isFilter: 'on', FilterMode: mode === 'White' ? '1' : '0', Selected_Menu: 'Security->MAC Filter'
  };
  const post = await httpPost(jar, MACFILTER_PATH, payload, MACFILTER_PATH);
  if (post.status !== 200) return { enforced: false, message: `Router returned HTTP ${post.status} on the delete request.` };

  return (await confirmPresence(jar, canon, false))
    ? { enforced: false, message: 'The router accepted the request but the device is still in its filter list, so the unblock did not take effect.' }
    : { enforced: true, message: 'Unblocked on the router.' };
}

// -------------------------------------------------------------------- public API

async function setBlocked(mac, blocked) {
  if (!isConfigured()) {
    return {
      enforced: false,
      message: blocked
        ? 'Marked as blocked in this panel only. Router blocking is off (set enabled:true and your login in router.js), so this device still has internet. Or change your Wi-Fi password to remove it.'
        : 'Unblocked in this panel.'
    };
  }

  const jar = makeJar();
  try {
    const auth = await login(jar);
    if (!auth.ok) return { enforced: false, message: auth.message };

    if (!(await hasMacFilter(jar))) {
      await logout(jar);
      return { enforced: false, message: 'Signed in, but this account exposes no MAC-filter page. ISP-locked units often hide it — ask your ISP for the superadmin account, or change the Wi-Fi password instead.' };
    }

    const result = blocked ? await atpAdd(jar, mac) : await atpRemove(jar, mac);
    await logout(jar);
    return result;
  } catch (e) {
    try { await logout(jar); } catch (_) { /* ignore */ }
    return { enforced: false, message: `Could not reach the router: ${e.message}` };
  }
}

module.exports = {
  isConfigured,
  setBlocked,
  // exported for tests
  _internals: { loginChallenge, checkCode, newSessionId, parseInputs, listEntries, menuPaths, filterMode }
};
