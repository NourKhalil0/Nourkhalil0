#!/usr/bin/env python3
"""
Fetches LIVE C2 botnet data from abuse.ch Feodo Tracker,
does GeoIP lookups via ip-api.com, and generates a dot-matrix
world threat map SVG with animated flowing attack lines.

Designed to run as a GitHub Action on a schedule.
"""
import json, math, os, struct, sys, time, urllib.request, zipfile
from datetime import datetime, timezone

# ============ FETCH LIVE THREAT DATA ============
print("[1/4] Fetching live C2 data from abuse.ch...")
import csv, io

CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv"
req = urllib.request.Request(CSV_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=30) as resp:
    text = resp.read().decode()

# Parse CSV: columns are first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
c2_entries = []
reader = csv.reader(io.StringIO(text))
for row in reader:
    if not row or row[0].startswith("#") or row[0] == "first_seen_utc":
        continue
    if len(row) >= 6:
        ip = row[1].strip()
        status = row[3].strip()
        malware = row[5].strip()
        last_online = row[4].strip()
        if ip.count(".") == 3:
            c2_entries.append({"ip": ip, "status": status, "malware": malware, "last_online": last_online})

# Prefer online/recent C2s, then fill with offline ones
online = [e for e in c2_entries if e["status"] == "online"]
offline = [e for e in c2_entries if e["status"] != "online"]
# Sort offline by last_online descending (most recent first)
offline.sort(key=lambda x: x["last_online"], reverse=True)
selected = online + offline[:max(0, 80 - len(online))]
c2_ips = list(set(e["ip"] for e in selected))[:80]
# Build malware lookup
ip_malware = {e["ip"]: e["malware"] for e in selected}
print(f"  Got {len(c2_ips)} unique C2 IPs")

# ============ GEOIP LOOKUPS ============
print("[2/4] GeoIP lookups via ip-api.com (batch)...")

# ip-api.com supports batch of up to 100
batch_size = 100
geolocated = []

for batch_start in range(0, len(c2_ips), batch_size):
    batch = c2_ips[batch_start:batch_start+batch_size]
    payload = json.dumps(batch).encode()
    req = urllib.request.Request(
        "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            results = json.loads(resp.read().decode())
        for r in results:
            if r.get("status") == "success" and r.get("lat") and r.get("lon"):
                geolocated.append({
                    "ip": r["query"],
                    "city": r.get("city", "Unknown"),
                    "country": r.get("country", "Unknown"),
                    "cc": r.get("countryCode", "??"),
                    "lat": r["lat"],
                    "lon": r["lon"],
                })
    except Exception as e:
        print(f"  Batch GeoIP error: {e}")
    if batch_start + batch_size < len(c2_ips):
        time.sleep(1.5)  # Rate limit

print(f"  Geolocated {len(geolocated)} C2 servers")

# ============ BUILD ATTACK PAIRS ============
# Group by country, then create attack flows between countries
from collections import defaultdict
by_country = defaultdict(list)
for g in geolocated:
    by_country[g["cc"]].append(g)

# Known target countries (major cyber attack targets)
TARGET_CITIES = [
    (38.89, -77.04, "Washington", "US"),
    (51.51, -0.13, "London", "GB"),
    (52.52, 13.40, "Berlin", "DE"),
    (48.86, 2.35, "Paris", "FR"),
    (35.69, 139.69, "Tokyo", "JP"),
    (37.57, 126.98, "Seoul", "KR"),
    (-33.87, 151.21, "Sydney", "AU"),
    (45.50, -73.57, "Montreal", "CA"),
    (59.91, 10.75, "Oslo", "NO"),
    (52.37, 4.90, "Amsterdam", "NL"),
    (50.45, 30.52, "Kyiv", "UA"),
    (32.07, 34.78, "Tel Aviv", "IL"),
    (1.35, 103.82, "Singapore", "SG"),
    (55.68, 12.57, "Copenhagen", "DK"),
    (60.17, 24.94, "Helsinki", "FI"),
]

# Create attack pairs: each C2 server attacks a random target
import random
random.seed(int(datetime.now(timezone.utc).timestamp()) // 3600)  # Changes hourly

attacks = []
colors = ["#ff2d55", "#ff6b35", "#ffcc00", "#ff3399", "#00ccff", "#bf5af2", "#ff453a", "#00ff88"]
attack_types = ["C2 Beacon", "Data Exfil", "Lateral Move", "Credential Theft",
                "Ransomware C2", "DDoS Command", "Backdoor Active", "Phishing C2"]

used_pairs = set()
for g in geolocated:
    # Pick a target that isn't the same country
    targets = [t for t in TARGET_CITIES if t[3] != g["cc"]]
    if not targets:
        targets = TARGET_CITIES
    target = random.choice(targets)

    pair_key = f"{g['cc']}-{target[3]}"
    if pair_key in used_pairs and len(attacks) > 10:
        continue  # Avoid too many duplicate routes
    used_pairs.add(pair_key)

    attacks.append({
        "src_lat": g["lat"], "src_lon": g["lon"],
        "src_city": g["city"], "src_cc": g["cc"],
        "dst_lat": target[0], "dst_lon": target[1],
        "dst_city": target[2], "dst_cc": target[3],
        "ip": g["ip"],
        "atype": random.choice(attack_types),
        "color": random.choice(colors),
    })

# Limit to ~25 for SVG performance
attacks = attacks[:25]
print(f"  Created {len(attacks)} attack flows")

# ============ WORLD MAP DOTS ============
print("[3/4] Generating dot-matrix world map...")
SHP_DIR = "/tmp/ne_land"
NE_URL = "https://naciscdn.org/naturalearth/110m/physical/ne_110m_land.zip"

if not os.path.exists(os.path.join(SHP_DIR, "ne_110m_land.shp")):
    urllib.request.urlretrieve(NE_URL, "/tmp/ne_land.zip")
    with zipfile.ZipFile("/tmp/ne_land.zip", 'r') as z:
        z.extractall(SHP_DIR)

def read_shp(path):
    polygons = []
    with open(path, 'rb') as f:
        f.read(100)
        while True:
            rec = f.read(8)
            if len(rec) < 8: break
            _, cl = struct.unpack('>ii', rec)
            content = f.read(cl * 2)
            if len(content) < 4: break
            st = struct.unpack('<i', content[0:4])[0]
            if st != 5: continue
            off = 36
            np_ = struct.unpack('<i', content[off:off+4])[0]
            npt = struct.unpack('<i', content[off+4:off+8])[0]
            off += 8
            parts = [struct.unpack('<i', content[off+p*4:off+p*4+4])[0] for p in range(np_)]
            off += np_ * 4
            pts = []
            for _ in range(npt):
                x, y = struct.unpack('<dd', content[off:off+16]); pts.append((x, y)); off += 16
            for pi in range(np_):
                s = parts[pi]; e = parts[pi+1] if pi+1 < np_ else npt
                r = pts[s:e]
                if len(r) >= 3: polygons.append(r)
    return polygons

def pip(x, y, poly):
    n = len(poly); inside = False; j = n - 1
    for i in range(n):
        xi, yi = poly[i]; xj, yj = poly[j]
        if ((yi > y) != (yj > y)) and (x < (xj-xi)*(y-yi)/(yj-yi)+xi): inside = not inside
        j = i
    return inside

polys = read_shp(os.path.join(SHP_DIR, "ne_110m_land.shp"))
dots = []
lat = 85
while lat >= -60:
    lon = -180
    while lon <= 180:
        for p in polys:
            if pip(lon, lat, p): dots.append((lon, lat)); break
        lon += 2.5
    lat -= 2.5
print(f"  {len(dots)} land dots")

# ============ BUILD SVG ============
print("[4/4] Building SVG...")
W, H = 900, 480
MX, MY, MW, MH = 20, 55, 860, 380

def g2s(lat, lon):
    x = MX + ((lon+180)/360)*MW
    lr = math.radians(min(max(lat,-60),85))
    lx, ln = math.radians(85), math.radians(-60)
    yn = (math.log(math.tan(math.pi/4+lx/2))-math.log(math.tan(math.pi/4+lr/2)))/(math.log(math.tan(math.pi/4+lx/2))-math.log(math.tan(math.pi/4+ln/2)))
    return x, MY+yn*MH

now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
svg = [f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">
  <rect width="{W}" height="{H}" rx="10" fill="#1a1a2e"/>
  <rect x="0" y="0" width="{W//3}" height="3" fill="#ff2d55"/>
  <rect x="{W//3}" y="0" width="{W//3}" height="3" fill="#ff6b35"/>
  <rect x="{W*2//3}" y="0" width="{W//3+1}" height="3" fill="#ffcc00"/>
  <text x="{W//2}" y="28" fill="#ffffff" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="bold" text-anchor="middle" letter-spacing="3">LIVE CYBER THREAT MAP</text>
  <text x="{W//2}" y="45" fill="#ff2d55" font-family="Arial,Helvetica,sans-serif" font-size="9" text-anchor="middle" letter-spacing="1">{len(attacks)} ACTIVE C2 THREATS — UPDATED {now_str} — SOURCE: ABUSE.CH FEODO TRACKER</text>
''']

# Grid
for lg in range(-60,90,30):
    _,y=g2s(lg,0); svg.append(f'  <line x1="{MX}" y1="{y:.1f}" x2="{MX+MW}" y2="{y:.1f}" stroke="#2a2a4a" stroke-width="0.3"/>')
for lo in range(-180,181,30):
    x,_=g2s(0,lo); svg.append(f'  <line x1="{x:.1f}" y1="{MY}" x2="{x:.1f}" y2="{MY+MH}" stroke="#2a2a4a" stroke-width="0.3"/>')

# Land
for lon,lat in dots:
    x,y=g2s(lat,lon); svg.append(f'  <circle cx="{x:.1f}" cy="{y:.1f}" r="1.5" fill="#3a3a5c" opacity="0.6"/>')

# Attacks
td = 36
na = len(attacks)

for i, a in enumerate(attacks):
    sx,sy = g2s(a["src_lat"],a["src_lon"])
    ex,ey = g2s(a["dst_lat"],a["dst_lon"])
    c = a["color"]

    mx,my = (sx+ex)/2,(sy+ey)/2
    d = math.sqrt((ex-sx)**2+(ey-sy)**2)
    nx = -(ey-sy)/max(d,1)*min(d*0.2,50)
    ny = (ex-sx)/max(d,1)*min(d*0.2,50)
    cpx,cpy = mx+nx, my+ny
    pl = d*1.15

    ph = (i/na)*td
    w = 6.0

    def in_win(s, start, dur):
        end = start+dur
        if end <= td: return start <= s < end
        return s >= start or s < (end-td)

    vis = ";".join("1" if in_win(s,ph,w) else "0" for s in range(td))
    src = ";".join("1" if in_win(s,ph,1.5) else "0" for s in range(td))
    dst = ";".join("1" if in_win(s,ph+2.5,w-2.5) else "0" for s in range(td))
    lbl = ";".join("1" if in_win(s,ph+1.5,w-2.5) else "0" for s in range(td))

    ds = 8
    dg = max(4, pl-ds)

    svg.append(f'''
  <!-- {a["ip"]}: {a["src_city"]} → {a["dst_city"]} ({a["atype"]}) -->
  <path d="M{sx:.1f},{sy:.1f} Q{cpx:.1f},{cpy:.1f} {ex:.1f},{ey:.1f}" fill="none" stroke="{c}" stroke-width="1.5" opacity="0" stroke-dasharray="{ds} {dg:.0f}">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{vis}" calcMode="discrete"/>
    <animate attributeName="stroke-dashoffset" from="{pl:.0f}" to="0" dur="2s" repeatCount="indefinite"/>
  </path>
  <path d="M{sx:.1f},{sy:.1f} Q{cpx:.1f},{cpy:.1f} {ex:.1f},{ey:.1f}" fill="none" stroke="{c}" stroke-width="0.4" opacity="0">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{vis}" calcMode="discrete"/>
  </path>
  <circle cx="{sx:.1f}" cy="{sy:.1f}" r="2" fill="{c}" opacity="0">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{vis}" calcMode="discrete"/>
  </circle>
  <circle cx="{sx:.1f}" cy="{sy:.1f}" r="3" fill="none" stroke="{c}" stroke-width="0.5" opacity="0">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{src}" calcMode="discrete"/>
    <animate attributeName="r" values="3;10;3" dur="1.5s" repeatCount="indefinite"/>
  </circle>
  <text x="{sx:.1f}" y="{sy-8:.1f}" fill="{c}" font-family="Arial,Helvetica,sans-serif" font-size="7" font-weight="bold" text-anchor="middle" opacity="0">{a["src_city"]}<animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{vis}" calcMode="discrete"/></text>
  <circle cx="{ex:.1f}" cy="{ey:.1f}" r="2" fill="{c}" opacity="0">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{dst}" calcMode="discrete"/>
  </circle>
  <circle cx="{ex:.1f}" cy="{ey:.1f}" r="3" fill="none" stroke="{c}" stroke-width="1" opacity="0">
    <animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{dst}" calcMode="discrete"/>
    <animate attributeName="r" values="3;14;3" dur="1s" repeatCount="indefinite"/>
  </circle>
  <text x="{ex:.1f}" y="{ey-8:.1f}" fill="{c}" font-family="Arial,Helvetica,sans-serif" font-size="7" font-weight="bold" text-anchor="middle" opacity="0">{a["dst_city"]}<animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{dst}" calcMode="discrete"/></text>
  <text x="{cpx:.1f}" y="{cpy-6:.1f}" fill="{c}" font-family="monospace" font-size="5.5" text-anchor="middle" opacity="0">{a["atype"]}<animate attributeName="opacity" dur="{td}s" repeatCount="indefinite" values="{lbl}" calcMode="discrete"/></text>''')

# Bottom
py = MY+MH+10
svg.append(f'''
  <rect x="0" y="{py}" width="{W}" height="36" fill="#12122a"/>
  <rect x="0" y="{py}" width="{W}" height="1" fill="#2a2a4a"/>
  <circle cx="25" cy="{py+18}" r="3" fill="#00ff88"><animate attributeName="opacity" values="1;0.3;1" dur="1.5s" repeatCount="indefinite"/></circle>
  <text x="33" y="{py+21}" fill="#00ff88" font-family="Arial,Helvetica,sans-serif" font-size="8" font-weight="bold">LIVE — {len(geolocated)} C2 servers in {len(by_country)} countries</text>
  <text x="{W//2}" y="{py+21}" fill="#555577" font-family="Arial,Helvetica,sans-serif" font-size="7" text-anchor="middle">Data: abuse.ch Feodo Tracker | Updated: {now_str}</text>
  <text x="{W-25}" y="{py+21}" fill="#ff2d55" font-family="Arial,Helvetica,sans-serif" font-size="9" font-weight="bold" text-anchor="end">{len(attacks)}<animate attributeName="opacity" values="1;0.5;1" dur="1s" repeatCount="indefinite"/></text>
  <text x="{W-25}" y="{py+13}" fill="#555577" font-family="Arial,Helvetica,sans-serif" font-size="6" text-anchor="end">threats</text>
''')
svg.append('</svg>')

out = "threatmap-v2.svg"
with open(out, 'w') as f:
    f.write('\n'.join(svg))
print(f"Done! {out} ({os.path.getsize(out)} bytes) — {len(attacks)} live threats from {len(geolocated)} C2s")
