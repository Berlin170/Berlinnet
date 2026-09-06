// ---------------------------------------------------------------------------
// discovery.js
//
// PC-side device identification. Randomised MACs mean the ARP table can't tell
// us WHAT a device is any more, so instead we ask the devices themselves:
//
//   - mDNS / Bonjour   (Apple, Chromecast, printers, smart-home, some Androids)
//   - SSDP / UPnP      (smart TVs, media players, some routers)
//   - NetBIOS          (Windows PCs)
//   - reverse DNS      (anything the router named)
//   - open-port shape  (fingerprint the kind of device from what it exposes)
//
// Everything here uses Node built-ins only. Each probe is best-effort and
// silent on failure — a quiet network simply yields fewer names.
// ---------------------------------------------------------------------------

const dgram = require('dgram');
const net = require('net');
const http = require('http');
const dns = require('dns');
const { exec } = require('child_process');

// ---------------------------------------------------------------------------
// mDNS (multicast DNS) — UDP 5353 to 224.0.0.251
// ---------------------------------------------------------------------------

// The services worth asking about. Each answer tends to carry a human name
// (Apple's "fn", cast "fn", the instance label) plus a model hint.
const MDNS_SERVICES = [
  '_services._dns-sd._udp.local',
  '_device-info._tcp.local',
  '_companion-link._tcp.local', // Apple continuity
  '_googlecast._tcp.local',     // Chromecast / Android TV / Google speakers
  '_airplay._tcp.local',        // Apple TV, AirPlay speakers
  '_raop._tcp.local',           // AirPlay audio
  '_spotify-connect._tcp.local',
  '_amzn-wplay._tcp.local',     // Amazon devices
  '_printer._tcp.local',
  '_ipp._tcp.local',
  '_http._tcp.local',
  '_workstation._tcp.local',    // avahi (Linux)
  '_smb._tcp.local'
];

function encodeName(name) {
  const out = [];
  for (const label of name.split('.')) {
    if (!label) continue;
    out.push(label.length);
    for (const ch of label) out.push(ch.charCodeAt(0));
  }
  out.push(0);
  return out;
}

function buildMdnsQuery(name) {
  const header = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // 1 question, QM
  const q = encodeName(name).concat([0, 12, 0, 1]);     // QTYPE=PTR, QCLASS=IN
  return Buffer.from(header.concat(q));
}

// Read a (possibly compressed) DNS name starting at offset. Returns
// { name, next } where next is the offset just past the name in the record
// stream (pointers do not advance the stream beyond their two bytes).
function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let jumped = false;
  let next = offset;
  let guard = 0;

  while (guard++ < 128) {
    if (pos >= buf.length) break;
    const len = buf[pos];

    if (len === 0) {
      if (!jumped) next = pos + 1;
      break;
    }

    if ((len & 0xc0) === 0xc0) {           // compression pointer
      if (pos + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) next = pos + 2;
      jumped = true;
      pos = ptr;
      continue;
    }

    labels.push(buf.toString('utf8', pos + 1, pos + 1 + len));
    pos += 1 + len;
    if (!jumped) next = pos;
  }

  return { name: labels.join('.'), next };
}

function parseTxt(buf, start, len) {
  const out = {};
  let pos = start;
  const end = start + len;
  while (pos < end) {
    const l = buf[pos];
    pos += 1;
    if (l === 0 || pos + l > end) break;
    const pair = buf.toString('utf8', pos, pos + l);
    pos += l;
    const eq = pair.indexOf('=');
    if (eq > 0) out[pair.slice(0, eq).toLowerCase()] = pair.slice(eq + 1);
  }
  return out;
}

// Parse one mDNS packet into records we care about, keyed for later correlation.
function parseMdns(buf, store) {
  if (buf.length < 12) return;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const ar = buf.readUInt16BE(10);
  const total = an + ns + ar;

  let pos = 12;
  // skip questions
  for (let i = 0; i < qd && pos < buf.length; i++) {
    const r = readName(buf, pos);
    pos = r.next + 4;
  }

  for (let i = 0; i < total && pos < buf.length; i++) {
    const nameRes = readName(buf, pos);
    pos = nameRes.next;
    if (pos + 10 > buf.length) break;

    const type = buf.readUInt16BE(pos);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdStart = pos + 10;
    pos = rdStart + rdlen;
    if (pos > buf.length) break;

    if (type === 1 && rdlen === 4) {                 // A record: host -> IPv4
      const ip = `${buf[rdStart]}.${buf[rdStart + 1]}.${buf[rdStart + 2]}.${buf[rdStart + 3]}`;
      store.aRecords[nameRes.name.toLowerCase()] = ip;
    } else if (type === 12) {                        // PTR: service -> instance
      const target = readName(buf, rdStart).name;
      store.ptr.push({ service: nameRes.name, instance: target });
    } else if (type === 33) {                         // SRV: instance -> host
      const target = readName(buf, rdStart + 6).name;
      store.srv[nameRes.name.toLowerCase()] = target.toLowerCase();
    } else if (type === 16) {                          // TXT: instance -> kv
      store.txt[nameRes.name.toLowerCase()] = parseTxt(buf, rdStart, rdlen);
    }
  }
}

// A friendly name for one mDNS service instance, best field first.
function nameFromInstance(instance, store) {
  const txt = store.txt[instance.toLowerCase()] || {};
  if (txt.fn) return txt.fn;                       // cast / Apple friendly name
  if (txt.n) return txt.n;
  const label = instance.split('.')[0];
  return label ? decodeURIComponent(label.replace(/\\032/g, ' ')) : '';
}

function kindFromService(service) {
  if (service.includes('_googlecast')) return 'Chromecast / Cast';
  if (service.includes('_airplay') || service.includes('_raop')) return 'Apple / AirPlay';
  if (service.includes('_companion-link') || service.includes('_device-info')) return 'Apple device';
  if (service.includes('_spotify')) return 'Speaker';
  if (service.includes('_amzn')) return 'Amazon device';
  if (service.includes('_printer') || service.includes('_ipp')) return 'Printer';
  if (service.includes('_workstation') || service.includes('_smb')) return 'Computer';
  return '';
}

function runMdns(timeoutMs) {
  return new Promise((resolve) => {
    const store = { aRecords: {}, ptr: [], srv: {}, txt: {} };
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    sock.on('error', () => { try { sock.close(); } catch (e) {} resolve({}); });
    sock.on('message', (msg) => { try { parseMdns(msg, store); } catch (e) {} });

    const blast = () => {
      for (const svc of MDNS_SERVICES) {
        try { sock.send(buildMdnsQuery(svc), 5353, '224.0.0.251'); } catch (e) {}
      }
    };

    sock.bind(5353, () => {
      try { sock.addMembership('224.0.0.251'); } catch (e) {}
      blast();
    });

    // Devices answer mDNS sporadically, so keep asking across the window.
    const burst = setInterval(blast, 1000);

    setTimeout(() => {
      clearInterval(burst);
      try { sock.close(); } catch (e) {}

      // Correlate: PTR gives service+instance, SRV maps instance->host,
      // A maps host->IP. Fold everything down to per-IP name + kind.
      const byIp = {};
      for (const { service, instance } of store.ptr) {
        const host = store.srv[instance.toLowerCase()];
        const ip = host ? store.aRecords[host] : null;
        if (!ip) continue;
        const nm = nameFromInstance(instance, store);
        const kind = kindFromService(service);
        if (!byIp[ip]) byIp[ip] = { name: '', kind: '', source: 'mDNS' };
        if (nm && !byIp[ip].name) byIp[ip].name = nm;
        if (kind && !byIp[ip].kind) byIp[ip].kind = kind;
      }
      // A records with no service still give a hostname per IP.
      for (const [host, ip] of Object.entries(store.aRecords)) {
        if (!byIp[ip]) {
          const label = host.replace(/\.local\.?$/i, '');
          byIp[ip] = { name: label, kind: '', source: 'mDNS' };
        }
      }
      resolve(byIp);
    }, timeoutMs);
  });
}

// ---------------------------------------------------------------------------
// SSDP / UPnP — UDP 1900 M-SEARCH, then fetch the device description XML
// ---------------------------------------------------------------------------

function fetchXml(location, timeoutMs) {
  return new Promise((resolve) => {
    let url;
    try { url = new URL(location); } catch (e) { return resolve(null); }
    if (url.protocol !== 'http:') return resolve(null);

    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });
      res.on('end', () => resolve(body));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function tagText(xml, tag) {
  const m = xml.match(new RegExp('<' + tag + '[^>]*>([^<]+)</' + tag + '>', 'i'));
  return m ? m[1].trim() : '';
}

function kindFromUpnp(deviceType, model, name) {
  const hay = (deviceType + ' ' + model + ' ' + name).toLowerCase();
  if (hay.includes('mediarenderer') || hay.includes('tv')) return 'Smart TV / Media';
  if (hay.includes('printer')) return 'Printer';
  if (hay.includes('internetgateway') || hay.includes('router')) return 'Router';
  if (hay.includes('nas') || hay.includes('storage')) return 'Storage / NAS';
  return 'UPnP device';
}

function runSsdp(timeoutMs) {
  return new Promise((resolve) => {
    const found = {};       // ip -> LOCATION url
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const msearch = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\n' +
      'HOST: 239.255.255.250:1900\r\n' +
      'MAN: "ssdp:discover"\r\n' +
      'MX: 2\r\n' +
      'ST: ssdp:all\r\n\r\n'
    );

    sock.on('error', () => { try { sock.close(); } catch (e) {} resolve({}); });
    sock.on('message', (msg, rinfo) => {
      const text = msg.toString('utf8');
      const loc = text.match(/LOCATION:\s*(\S+)/i);
      if (loc && !found[rinfo.address]) found[rinfo.address] = loc[1].trim();
    });

    const blast = () => {
      try { sock.send(msearch, 1900, '239.255.255.250'); } catch (e) {}
    };

    sock.bind(() => {
      try { sock.setBroadcast(true); } catch (e) {}
      blast();
    });

    const burst = setInterval(blast, 1000);

    setTimeout(async () => {
      clearInterval(burst);
      try { sock.close(); } catch (e) {}
      const byIp = {};
      const budget = Math.max(1500, timeoutMs);
      await Promise.all(Object.entries(found).map(async ([ip, loc]) => {
        const xml = await fetchXml(loc, 2500);
        if (!xml) { byIp[ip] = { name: '', kind: 'UPnP device', source: 'SSDP' }; return; }
        const name = tagText(xml, 'friendlyName');
        const model = tagText(xml, 'modelName');
        const dtype = tagText(xml, 'deviceType');
        byIp[ip] = {
          name: name || model,
          kind: kindFromUpnp(dtype, model, name),
          source: 'SSDP'
        };
      }));
      void budget;
      resolve(byIp);
    }, timeoutMs);
  });
}

// ---------------------------------------------------------------------------
// per-host probes: NetBIOS, reverse DNS, open-port fingerprint
// ---------------------------------------------------------------------------

function reverseDns(ip, timeoutMs) {
  return new Promise((resolve) => {
    const done = (v) => resolve(v);
    const timer = setTimeout(() => done(''), timeoutMs);
    dns.reverse(ip, (err, names) => {
      clearTimeout(timer);
      if (err || !names || !names.length) return done('');
      done(names[0].replace(/\.(local|lan|home|localdomain)\.?$/i, ''));
    });
  });
}

function netbiosName(ip, timeoutMs) {
  if (process.platform !== 'win32') return Promise.resolve('');
  return new Promise((resolve) => {
    exec(`nbtstat -A ${ip}`, { timeout: timeoutMs }, (err, stdout) => {
      if (err || !stdout) return resolve('');
      for (const line of stdout.split('\n')) {
        // "  NAME           <00>  UNIQUE      Registered"  — <00>/UNIQUE = machine
        const m = line.match(/^\s*([^\s<]+)\s+<00>\s+UNIQUE/i);
        if (m) return resolve(m[1].trim());
      }
      resolve('');
    });
  });
}

// Which ports we knock on, and what each one implies.
const PORT_HINTS = [
  { port: 62078, kind: 'iPhone / iPad' },
  { port: 8009,  kind: 'Chromecast / Cast' },
  { port: 7000,  kind: 'Apple / AirPlay' },
  { port: 5555,  kind: 'Android (ADB)' },
  { port: 9100,  kind: 'Printer' },
  { port: 631,   kind: 'Printer' },
  { port: 445,   kind: 'Windows PC' },
  { port: 139,   kind: 'Windows PC' },
  { port: 3389,  kind: 'Windows PC' },
  { port: 22,    kind: 'Computer (SSH)' },
  { port: 548,   kind: 'Mac / Apple' },
  { port: 1400,  kind: 'Sonos speaker' },
  { port: 80,    kind: '' },   // generic — only used as a tiebreaker below
  { port: 443,   kind: '' },
  { port: 53,    kind: '' }
];

function probePort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const finish = (open) => { if (!settled) { settled = true; sock.destroy(); resolve(open); } };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, ip);
  });
}

async function fingerprint(ip, isRouter, timeoutMs) {
  const openPorts = [];
  await Promise.all(PORT_HINTS.map(async ({ port }) => {
    if (await probePort(ip, port, timeoutMs)) openPorts.push(port);
  }));

  const open = new Set(openPorts);
  let kind = '';
  // The gateway is the router, whatever else it happens to expose (fiber ONTs
  // often leave 5555/telnet-style ports open) — don't let a port hint win here.
  if (isRouter) return { kind: 'Router', openPorts };
  // Otherwise the first specific hint whose port is open wins.
  for (const { port, kind: k } of PORT_HINTS) {
    if (k && open.has(port)) { kind = k; break; }
  }
  if (!kind && (open.has(80) || open.has(443))) kind = 'Has web page';

  return { kind, openPorts };
}

// ---------------------------------------------------------------------------
// public entry point
// ---------------------------------------------------------------------------

// hosts: [{ ip, isRouter, isThisPC }]
// returns: { [ip]: { name, kind, source, openPorts } }
async function identify(hosts, opts = {}) {
  const mdnsMs = opts.mdnsMs || 4000;
  const ssdpMs = opts.ssdpMs || 3000;
  const perHostMs = opts.perHostMs || 1500;

  // Broadcast probes run once for the whole network, in parallel.
  const [mdns, ssdp] = await Promise.all([
    runMdns(mdnsMs).catch(() => ({})),
    runSsdp(ssdpMs).catch(() => ({}))
  ]);

  const result = {};

  await Promise.all(hosts.map(async (h) => {
    const ip = h.ip;
    const entry = { name: '', kind: '', source: '', openPorts: [] };

    // Name: prefer mDNS, then SSDP, then NetBIOS, then reverse DNS.
    const m = mdns[ip];
    const s = ssdp[ip];
    if (m) { if (m.name) { entry.name = m.name; entry.source = 'mDNS'; } if (m.kind) entry.kind = m.kind; }
    if (s) { if (!entry.name && s.name) { entry.name = s.name; entry.source = 'SSDP'; } if (!entry.kind && s.kind) entry.kind = s.kind; }

    if (!entry.name) {
      const [nb, rev] = await Promise.all([
        netbiosName(ip, perHostMs + 1000),
        reverseDns(ip, perHostMs)
      ]);
      if (nb) { entry.name = nb; entry.source = 'NetBIOS'; if (!entry.kind) entry.kind = 'Windows PC'; }
      else if (rev) { entry.name = rev; entry.source = 'DNS'; }
    }

    // Kind: fall back to a port fingerprint when nothing said what it is.
    if (!entry.kind || !entry.name) {
      const fp = await fingerprint(ip, h.isRouter, perHostMs);
      entry.openPorts = fp.openPorts;
      if (!entry.kind && fp.kind) entry.kind = fp.kind;
    }

    if (h.isRouter && !entry.kind) entry.kind = 'Router';
    if (h.isThisPC) { entry.kind = 'This PC'; if (!entry.name) entry.name = 'This PC'; }

    result[ip] = entry;
  }));

  return result;
}

module.exports = { identify };
