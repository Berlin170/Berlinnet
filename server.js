const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

const router = require('./router');
const discovery = require('./discovery');

const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'devices.json');
const VENDOR_FILE = path.join(__dirname, 'vendors.json');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------

function loadJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

function saveJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('could not write', file, e.message);
  }
}

// devices keyed by MAC. { mac, ip, name, vendor, trusted, blocked, firstSeen, lastSeen }
let devices = loadJSON(DATA_FILE, {});
let vendorCache = loadJSON(VENDOR_FILE, {});

let scanState = { running: false, lastScan: null, lastError: null };

// ---------------------------------------------------------------------------
// network helpers
// ---------------------------------------------------------------------------

function normalizeMac(mac) {
  return mac.toLowerCase().replace(/[^0-9a-f]/g, '').match(/.{1,2}/g).join(':');
}

function isRealMac(mac) {
  const clean = mac.replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (clean.length !== 12) return false;
  if (clean === 'ffffffffffff') return false;      // broadcast
  if (clean === '000000000000') return false;      // null
  if (clean.startsWith('01005e')) return false;    // ipv4 multicast
  if (clean.startsWith('3333')) return false;      // ipv6 multicast
  return true;
}

// Work out the local subnet, e.g. "192.168.1"
function getSubnet() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        const parts = net.address.split('.');
        return { base: parts.slice(0, 3).join('.'), self: net.address };
      }
    }
  }
  return { base: '192.168.1', self: null };
}

// Ping every address on the subnet so the ARP table fills up.
function pingSweep(base) {
  const isWin = process.platform === 'win32';
  const jobs = [];

  for (let i = 1; i <= 254; i++) {
    const ip = `${base}.${i}`;
    const cmd = isWin
      ? `ping -n 1 -w 300 ${ip}`
      : `ping -c 1 -W 1 ${ip}`;

    jobs.push(new Promise((resolve) => {
      exec(cmd, { timeout: 2000 }, () => resolve());
    }));
  }

  return Promise.all(jobs);
}

// Read the ARP table and pull out ip + mac pairs.
function readArpTable() {
  return new Promise((resolve) => {
    exec('arp -a', { timeout: 8000 }, (err, stdout) => {
      if (err || !stdout) return resolve([]);

      const found = [];
      const lines = stdout.split('\n');

      for (const line of lines) {
        // matches both "192.168.1.5  aa-bb-cc-dd-ee-ff  dynamic"  (Windows)
        // and         "? (192.168.1.5) at aa:bb:cc:dd:ee:ff"      (Linux/mac)
        const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        const macMatch = line.match(/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/);

        if (ipMatch && macMatch) {
          const mac = macMatch[0];
          if (!isRealMac(mac)) continue;
          found.push({ ip: ipMatch[1], mac: normalizeMac(mac) });
        }
      }

      resolve(found);
    });
  });
}

// ---------------------------------------------------------------------------
// vendor lookup (who makes this device)
// ---------------------------------------------------------------------------

function lookupVendor(mac) {
  const prefix = mac.slice(0, 8);

  if (vendorCache[prefix]) return Promise.resolve(vendorCache[prefix]);

  return new Promise((resolve) => {
    const req = https.get(
      `https://api.macvendors.com/${encodeURIComponent(mac)}`,
      { timeout: 4000 },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          if (res.statusCode === 200 && body && !body.includes('{')) {
            const vendor = body.trim().slice(0, 60);
            vendorCache[prefix] = vendor;
            saveJSON(VENDOR_FILE, vendorCache);
            resolve(vendor);
          } else {
            vendorCache[prefix] = 'Unknown';
            resolve('Unknown');
          }
        });
      }
    );

    req.on('error', () => resolve('Unknown'));
    req.on('timeout', () => { req.destroy(); resolve('Unknown'); });
  });
}

// ---------------------------------------------------------------------------
// the scan
// ---------------------------------------------------------------------------

async function runScan() {
  if (scanState.running) return;

  scanState.running = true;
  scanState.lastError = null;

  try {
    const { base, self } = getSubnet();

    await pingSweep(base);
    // give the OS a moment to settle the ARP cache
    await new Promise((r) => setTimeout(r, 1500));

    const found = await readArpTable();
    const now = Date.now();
    const seenMacs = new Set();

    for (const entry of found) {
      const mac = entry.mac;
      seenMacs.add(mac);

      if (!devices[mac]) {
        devices[mac] = {
          mac,
          ip: entry.ip,
          name: '',
          vendor: '',
          trusted: false,
          blocked: false,
          firstSeen: now,
          lastSeen: now
        };
      } else {
        devices[mac].ip = entry.ip;
        devices[mac].lastSeen = now;
      }

      if (entry.ip === self) devices[mac].isThisPC = true;
    }

    // mark the router itself
    const gatewayIp = `${base}.1`;
    for (const mac of Object.keys(devices)) {
      if (devices[mac].ip === gatewayIp) devices[mac].isRouter = true;
      devices[mac].online = seenMacs.has(mac);
    }

    // ask the online devices what they are — randomised MACs tell us nothing,
    // so this is where names and device types actually come from.
    const onlineList = Object.values(devices).filter((d) => d.online);
    let identified = {};
    try {
      identified = await discovery.identify(
        onlineList.map((d) => ({ ip: d.ip, isRouter: !!d.isRouter, isThisPC: !!d.isThisPC })),
        { mdnsMs: 5000, ssdpMs: 4000, perHostMs: 1500 }
      );
    } catch (e) {
      console.error('identify failed:', e.message);
    }

    for (const d of onlineList) {
      const info = identified[d.ip];
      if (!info) continue;
      // Device type is re-derived every scan (it's cheap and can change).
      if (info.kind) d.kind = info.kind;
      d.openPorts = info.openPorts || [];
      // A discovered name is a suggestion; a name the user typed always wins
      // and is never overwritten.
      if (info.name) {
        d.discoveredName = info.name;
        d.discoveredVia = info.source;
      }
    }

    // fill in vendors for anything missing one
    const needVendor = Object.values(devices).filter((d) => !d.vendor);
    for (const d of needVendor) {
      d.vendor = await lookupVendor(d.mac);
    }

    scanState.lastScan = now;
    saveJSON(DATA_FILE, devices);
  } catch (e) {
    scanState.lastError = e.message;
    console.error('scan failed:', e.message);
  } finally {
    scanState.running = false;
  }
}

// ---------------------------------------------------------------------------
// api
// ---------------------------------------------------------------------------

app.get('/api/devices', (req, res) => {
  const list = Object.values(devices).sort((a, b) => {
    if (a.online !== b.online) return a.online ? -1 : 1;
    const aNum = parseInt(a.ip.split('.')[3], 10) || 0;
    const bNum = parseInt(b.ip.split('.')[3], 10) || 0;
    return aNum - bNum;
  });

  res.json({
    devices: list,
    scanning: scanState.running,
    lastScan: scanState.lastScan,
    lastError: scanState.lastError,
    routerConfigured: router.isConfigured(),
    online: list.filter((d) => d.online).length,
    unknown: list.filter((d) => d.online && !d.trusted && !d.isRouter && !d.isThisPC).length
  });
});

app.post('/api/scan', async (req, res) => {
  runScan();
  res.json({ started: true });
});

app.post('/api/device/:mac', (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!devices[mac]) return res.status(404).json({ error: 'Device not found' });

  const { name, trusted } = req.body;
  if (typeof name === 'string') devices[mac].name = name.slice(0, 40);
  if (typeof trusted === 'boolean') devices[mac].trusted = trusted;

  saveJSON(DATA_FILE, devices);
  res.json(devices[mac]);
});

app.post('/api/block/:mac', async (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!devices[mac]) return res.status(404).json({ error: 'Device not found' });

  const wantBlocked = req.body.blocked === true;
  const result = await router.setBlocked(mac, wantBlocked);

  devices[mac].blocked = wantBlocked;
  devices[mac].blockEnforced = result.enforced;
  saveJSON(DATA_FILE, devices);

  res.json({ device: devices[mac], enforced: result.enforced, message: result.message });
});

app.listen(PORT, () => {
  console.log(`\n  Network panel running at http://localhost:${PORT}\n`);
  runScan();
  setInterval(runScan, 5 * 60 * 1000); // rescan every 5 minutes
});
