// ---------- password strength ----------
function checkPw() {
  const pw = document.getElementById("pw").value;
  const res = document.getElementById("result");
  if (!res) return;

  if (!pw) {
    res.textContent = "Start typing to see a score.";
    return;
  }

  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const labels = [
    "Very weak — do not use.",
    "Weak — add length and variety.",
    "Reasonable — but could be stronger.",
    "Strong.",
    "Very strong."
  ];

  res.textContent = "Score: " + labels[score];
}

// ---------- phishing scanner ----------
function scanEmail() {
  const el = document.getElementById("email");
  const report = document.getElementById("report");
  if (!el || !report) return;

  const txt = el.value.toLowerCase();
  const flags = [];

  if (txt.includes("urgent")) flags.push("- Uses urgency language.");
  if (txt.includes("click here")) flags.push("- Contains 'click here'.");
  if (txt.includes("verify your account")) flags.push("- Asks you to verify your account.");
  if (/bit\.ly|tinyurl|\.ru\b/.test(txt)) flags.push("- Contains a shortened or suspicious URL.");
  if (txt.includes("password")) flags.push("- Mentions passwords.");
  if (txt.includes("suspend")) flags.push("- Threatens suspension of your account.");

  if (flags.length === 0) {
    report.textContent =
      "No obvious indicators found. This does not mean the email is safe — " +
      "always verify the sender through a separate channel.";
  } else {
    report.textContent =
      "Indicators found:\n" + flags.join("\n") +
      "\n\nDo not click links or reply. Report to your security team.";
  }
}

// ---------- IP / URL checker ----------
function checkTarget() {
  const el = document.getElementById("target");
  const out = document.getElementById("targetReport");
  if (!el || !out) return;

  const raw = el.value.trim();
  if (!raw) {
    out.textContent = "Enter an IP address or URL first.";
    return;
  }

  const lines = [];
  let risk = 0;

  // try to parse as IP first
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  if (ipv4.test(raw)) {
    lines.push("Type: IPv4 address");
    const parts = raw.split(".").map(Number);
    const valid = parts.every(p => p >= 0 && p <= 255);
    if (!valid) {
      lines.push("- Not a valid IPv4 address (octet out of range).");
      risk += 3;
    } else {
      const [a, b] = parts;
      if (a === 10) lines.push("- Range: private (10.0.0.0/8)");
      else if (a === 172 && b >= 16 && b <= 31) lines.push("- Range: private (172.16.0.0/12)");
      else if (a === 192 && b === 168) lines.push("- Range: private (192.168.0.0/16)");
      else if (a === 127) lines.push("- Range: loopback (127.0.0.0/8)");
      else if (a === 169 && b === 254) lines.push("- Range: link-local (APIPA)");
      else {
        lines.push("- Range: public internet-facing");
        risk += 1;
      }
    }
  } else {
    // treat as URL / hostname
    let url = raw;
    if (!/^https?:\/\//i.test(url)) url = "http://" + url;

    let host = "";
    try {
      host = new URL(url).hostname.toLowerCase();
      lines.push("Host: " + host);
    } catch (e) {
      out.textContent = "Could not parse that as a URL or IP.";
      return;
    }

    // TLD checks
    if (/\.ru$|\.cn$|\.tk$|\.top$|\.xyz$/.test(host)) {
      lines.push("- High-abuse TLD detected");
      risk += 2;
    }

    // shorteners
    if (/bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd/.test(host)) {
      lines.push("- Known URL shortener");
      risk += 2;
    }

    // IP-as-host
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      lines.push("- Hostname is a raw IP (unusual for legitimate sites)");
      risk += 2;
    }

    // punycode
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      lines.push("- Punycode domain (possible homograph attack)");
      risk += 2;
    }

    // long subdomain chains
    const labels = host.split(".");
    if (labels.length > 4) {
      lines.push("- Unusually long subdomain chain (" + labels.length + " labels)");
      risk += 1;
    }

    // hyphen stacking (typosquats often use this)
    if ((host.match(/-/g) || []).length >= 3) {
      lines.push("- Excessive hyphens in hostname (common in phishing domains)");
      risk += 1;
    }

    // protocol
    if (url.startsWith("http://")) {
      lines.push("- Uses HTTP, not HTTPS");
      risk += 1;
    } else {
      lines.push("- Uses HTTPS");
    }
  }

  let rating;
  if (risk === 0) rating = "Low concern based on static checks.";
  else if (risk <= 2) rating = "Moderate concern.";
  else if (risk <= 4) rating = "High concern — treat with caution.";
  else rating = "Very high concern — do not trust.";

  lines.push("");
  lines.push("Risk rating: " + rating);
  lines.push("(Static analysis only. Not a substitute for real threat intel.)");

  out.textContent = lines.join("\n");
}

// ---------- malware analysis simulator ----------
function analyseSample() {
  const el = document.getElementById("sample");
  const out = document.getElementById("malwareReport");
  if (!el || !out) return;

  const sample = el.value.trim();
  if (!sample) {
    out.textContent = "Enter a filename or hash first.";
    return;
  }

  const lines = [];
  lines.push("Sample: " + sample);
  lines.push("");

  const lower = sample.toLowerCase();

  // is it a hash?
  const isMd5 = /^[a-f0-9]{32}$/.test(lower);
  const isSha1 = /^[a-f0-9]{40}$/.test(lower);
  const isSha256 = /^[a-f0-9]{64}$/.test(lower);

  if (isMd5) lines.push("Identified as: MD5 hash");
  else if (isSha1) lines.push("Identified as: SHA-1 hash");
  else if (isSha256) lines.push("Identified as: SHA-256 hash");
  else if (sample.includes(".")) lines.push("Identified as: filename");

  // file extension analysis
  const exts = lower.split(".").slice(1);
  const doubleExt = exts.length >= 2;
  const riskyExt = exts.find(e => ["exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar", "dll", "hta"].includes(e));

  lines.push("");
  lines.push("Analysis");
  lines.push("--------");

  if (doubleExt && riskyExt) {
    lines.push("- Double extension detected — common masquerade technique");
    lines.push("  (e.g. invoice.pdf.exe tries to look like a PDF)");
  }

  if (riskyExt) {
    lines.push("- Executable extension: ." + riskyExt);
    lines.push("  Files like this can run code directly when opened.");
  }

  if (lower.includes("invoice") || lower.includes("receipt") || lower.includes("shipping")) {
    lines.push("- Filename mimics a common business document");
    lines.push("  (typical lure used in malspam campaigns)");
  }

  if (lower.includes("update") || lower.includes("patch")) {
    lines.push("- Filename mimics a software update");
    lines.push("  (fake updater is a common persistence lure)");
  }

  if (lower.includes("crack") || lower.includes("keygen") || lower.includes("free")) {
    lines.push("- Filename contains piracy/warez language");
    lines.push("  (common distribution vector for bundled malware)");
  }

  // simulated entropy
  const seed = sample.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const entropy = (5.5 + (seed % 250) / 100).toFixed(2);
  lines.push("- Entropy score: " + entropy + " / 8.0");
  if (entropy > 7.0) {
    lines.push("  High entropy — often indicates packing or encryption.");
  } else if (entropy > 6.0) {
    lines.push("  Elevated entropy — may indicate compression.");
  } else {
    lines.push("  Normal entropy — likely uncompressed.");
  }

  // simulated family guess based on hash prefix
  const families = [
    "Trojan.Generic",
    "Worm.USB",
    "Ransom.Cryptor",
    "Spy.Keylogger",
    "Backdoor.Remote",
    "Loader.Downloader",
    "Adware.Bundler"
  ];
  const familyIndex = seed % families.length;
  lines.push("- Threat family (simulated): " + families[familyIndex]);

  lines.push("");
  lines.push("Recommended action");
  lines.push("------------------");
  lines.push("- Do not execute outside an isolated sandbox.");
  lines.push("- Hash the file and check against VirusTotal.");
  lines.push("- Submit for full dynamic analysis if this was found in the wild.");
  lines.push("");
  lines.push("(This is a simulated report for educational purposes.)");

  out.textContent = lines.join("\n");
}

var gameState = {
  running: false,
  score: 0,
  missed: 0,
  timeLeft: 30,
  current: null,
  timer: null,
  eventTimer: null,
  totalEvents: 0
};

var trafficPool = [
  { label: "HTTP GET /index.html", source: "10.0.1.14", kind: "benign" },
  { label: "HTTPS POST /login", source: "10.0.1.22", kind: "benign" },
  { label: "DNS query for cdn.example.com", source: "10.0.1.9", kind: "benign" },
  { label: "NTP sync with pool.ntp.org", source: "10.0.0.1", kind: "benign" },
  { label: "SMTP outbound to mail provider", source: "10.0.2.11", kind: "benign" },
  { label: "SSH session from 10.0.1.5", source: "10.0.1.5", kind: "benign" },
  { label: "DHCP lease renewal", source: "10.0.0.2", kind: "benign" },
  { label: "ICMP echo request", source: "10.0.1.31", kind: "benign" },
  { label: "TCP 22 port scan sweep", source: "203.0.113.44", kind: "threat" },
  { label: "Repeated failed SSH logins", source: "198.51.100.7", kind: "threat" },
  { label: "SMB traffic to external host", source: "203.0.113.88", kind: "threat" },
  { label: "DNS query to known C2 domain", source: "10.0.1.14", kind: "threat" },
  { label: "Outbound traffic spike on port 4444", source: "10.0.3.6", kind: "threat" },
  { label: "HTTP POST to raw IP address", source: "203.0.113.201", kind: "threat" },
  { label: "RDP connection from public internet", source: "198.51.100.19", kind: "threat" },
  { label: "Unusual DNS TXT record exfiltration", source: "10.0.2.8", kind: "threat" },
  { label: "Base64-encoded HTTP payload", source: "10.0.1.44", kind: "threat" },
  { label: "Kerberos ticket request anomaly", source: "10.0.4.12", kind: "threat" }
];

function pickEvent() {
  return trafficPool[Math.floor(Math.random() * trafficPool.length)];
}

function stamp() {
  var d = new Date();
  var hh = String(d.getHours()).padStart(2, "0");
  var mm = String(d.getMinutes()).padStart(2, "0");
  var ss = String(d.getSeconds()).padStart(2, "0");
  return hh + ":" + mm + ":" + ss;
}

function appendLog(html) {
  var log = document.getElementById("gameLog");
  if (!log) return;
  var line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = '<span class="log-time">[' + stamp() + "]</span>" + html;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function updateHud() {
  var s = document.getElementById("gScore");
  var t = document.getElementById("gTime");
  var m = document.getElementById("gMissed");
  if (s) s.textContent = gameState.score;
  if (t) t.textContent = gameState.timeLeft;
  if (m) m.textContent = gameState.missed;
}

function nextEvent() {
  if (!gameState.running) return;
  var ev = pickEvent();
  gameState.current = ev;
  gameState.totalEvents++;
  appendLog(
    '<span class="event-line"><strong>' + ev.label + "</strong>from " +
    ev.source + "</span>"
  );
}

function gameAnswer(flagged) {
  if (!gameState.running || !gameState.current) return;
  var isThreat = gameState.current.kind === "threat";

  if (flagged && isThreat) {
    gameState.score += 10;
    appendLog('<span class="log-verdict-good">correct flag</span>');
  } else if (flagged && !isThreat) {
    gameState.score -= 5;
    appendLog('<span class="log-verdict-bad">false alarm -5</span>');
  } else if (!flagged && !isThreat) {
    gameState.score += 2;
    appendLog('<span class="log-verdict-good">correct allow</span>');
  } else {
    gameState.missed += 1;
    gameState.score -= 15;
    appendLog('<span class="log-verdict-bad">missed threat -15</span>');
  }

  gameState.current = null;
  updateHud();
  nextEvent();
}

function endGame() {
  gameState.running = false;
  clearInterval(gameState.timer);
  var over = document.getElementById("gameOver");
  var sum = document.getElementById("gameSummary");
  var controls = document.getElementById("gameControls");
  if (over) over.style.display = "block";
  if (controls) {
    document.getElementById("btnAllow").disabled = true;
    document.getElementById("btnFlag").disabled = true;
  }

  var rating;
  if (gameState.score >= 120 && gameState.missed === 0) rating = "Analyst of the shift.";
  else if (gameState.score >= 80) rating = "Solid detection work.";
  else if (gameState.score >= 40) rating = "Passable, but review your triage.";
  else if (gameState.score >= 0) rating = "Keep practising.";
  else rating = "You let things through. Run it again.";

  if (sum) {
    sum.textContent =
      "Final score: " + gameState.score +
      " | Missed threats: " + gameState.missed +
      " | Events reviewed: " + gameState.totalEvents +
      " | " + rating;
  }

  var sessions = parseInt(localStorage.getItem("cs_sessions") || "0", 10) + 1;
  localStorage.setItem("cs_sessions", sessions);
  var best = parseInt(localStorage.getItem("cs_best") || "0", 10);
  if (gameState.score > best) {
    localStorage.setItem("cs_best", gameState.score);
  }
}
var gameState = {
  running: false,
  score: 0,
  missed: 0,
  timeLeft: 30,
  current: null,
  timer: null,
  combo: 0,
  comboMultiplier: 1,
  totalEvents: 0,
  correctStreak: 0
};

var trafficPool = [

  { label: "HTTP GET /index.html", source: "10.0.1.14", ctx: "internal user, business hours", kind: "benign" },
  { label: "HTTPS POST /login", source: "10.0.1.22", ctx: "internal user, business hours", kind: "benign" },
  { label: "DNS query for cdn.example.com", source: "10.0.1.9", ctx: "normal CDN lookup", kind: "benign" },
  { label: "NTP sync with pool.ntp.org", source: "10.0.0.1", ctx: "scheduled time sync", kind: "benign" },
  { label: "SMTP outbound to mail provider", source: "10.0.2.11", ctx: "internal mail relay", kind: "benign" },
  { label: "DHCP lease renewal", source: "10.0.0.2", ctx: "routine", kind: "benign" },
  { label: "ICMP echo request", source: "10.0.1.31", ctx: "internal monitoring", kind: "benign" },
  { label: "HTTPS to storage provider", source: "10.0.1.7", ctx: "scheduled backup", kind: "benign" },

  { label: "SSH login", source: "10.0.1.5", ctx: "internal admin, 03:12, after 14 failed attempts", kind: "threat" },
  { label: "SSH login", source: "10.0.1.5", ctx: "internal admin, 10:30, valid key", kind: "benign" },
  { label: "HTTP request to raw IP", source: "10.0.3.6", ctx: "POST to 203.0.113.44, unusual for this host", kind: "threat" },
  { label: "Outbound traffic on port 4444", source: "10.0.3.6", ctx: "sustained, encrypted", kind: "threat" },
  { label: "RDP connection", source: "198.51.100.19", ctx: "from public internet, no VPN", kind: "threat" },
  { label: "DNS queries", source: "10.0.2.8", ctx: "burst of TXT records to single domain", kind: "threat" },
  { label: "SMB traffic to external host", source: "203.0.113.88", ctx: "outbound file share attempt", kind: "threat" },
  { label: "TCP port scan", source: "203.0.113.44", ctx: "sweep across 1-1024", kind: "threat" },
  { label: "Kerberos ticket request", source: "10.0.4.12", ctx: "anomalous service principal", kind: "threat" },
  { label: "Base64 payload in HTTP body", source: "10.0.1.44", ctx: "encoded, unusually large", kind: "threat" },

  { label: "DNS query for new domain", source: "10.0.1.16", ctx: "registered 2 days ago, low reputation", kind: "ambiguous" },
  { label: "Large outbound transfer", source: "10.0.2.4", ctx: "to cloud storage, 22:40", kind: "ambiguous" },
  { label: "Failed login attempts", source: "10.0.1.9", ctx: "3 attempts over 10 minutes, valid user", kind: "ambiguous" },
  { label: "HTTPS to foreign VPN provider", source: "10.0.3.18", ctx: "workstation, business hours", kind: "ambiguous" },
  { label: "New user account created", source: "10.0.4.2", ctx: "by admin, outside change window", kind: "ambiguous" },
  { label: "PowerShell outbound request", source: "10.0.1.52", ctx: "to known Microsoft endpoint", kind: "ambiguous" }

];

function pickEvent() {
  return trafficPool[Math.floor(Math.random() * trafficPool.length)];
}

function stamp() {
  var d = new Date();
  var hh = String(d.getHours()).padStart(2, "0");
  var mm = String(d.getMinutes()).padStart(2, "0");
  var ss = String(d.getSeconds()).padStart(2, "0");
  return hh + ":" + mm + ":" + ss;
}

function appendLog(html) {
  var log = document.getElementById("gameLog");
  if (!log) return;
  var line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = '<span class="log-time">[' + stamp() + "]</span>" + html;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function updateHud() {
  var s = document.getElementById("gScore");
  var t = document.getElementById("gTime");
  var m = document.getElementById("gMissed");
  var c = document.getElementById("gCombo");
  if (s) s.textContent = gameState.score;
  if (t) t.textContent = gameState.timeLeft;
  if (m) m.textContent = gameState.missed;
  if (c) {
    c.textContent = "x" + gameState.comboMultiplier;
    if (gameState.comboMultiplier > 1) {
      c.classList.add("combo-active");
    } else {
      c.classList.remove("combo-active");
    }
  }
}

function timeBetweenEvents() {
  var elapsed = 30 - gameState.timeLeft;
  if (elapsed < 10) return 3800;
  if (elapsed < 20) return 2600;
  return 1700;
}

function nextEvent() {
  if (!gameState.running) return;
  var ev = pickEvent();
  gameState.current = ev;
  gameState.totalEvents++;
  appendLog(
    '<span class="event-line"><strong>' + ev.label + "</strong>from " +
    ev.source + '<span class="event-ctx">' + ev.ctx + "</span></span>"
  );
}

function award(pts) {
  var total = pts * gameState.comboMultiplier;
  gameState.score += total;
  return total;
}

function correctAnswer() {
  gameState.correctStreak++;
  if (gameState.correctStreak >= 3) {
    gameState.comboMultiplier = Math.min(3, gameState.comboMultiplier + 1);
    gameState.correctStreak = 0;
    appendLog('<span class="log-verdict-good">combo up x' + gameState.comboMultiplier + "</span>");
  }
}

function wrongAnswer() {
  gameState.correctStreak = 0;
  gameState.comboMultiplier = 1;
}

function gameAnswer(action) {
  if (!gameState.running || !gameState.current) return;
  var ev = gameState.current;
  var verdict = "";
  var delta = 0;
  var correct = false;

  if (ev.kind === "benign") {
    if (action === "allow") { delta = award(2); verdict = "correct allow"; correct = true; }
    else if (action === "monitor") { delta = award(1); verdict = "monitored a benign event"; }
    else { delta = award(-6); verdict = "blocked a benign event"; }
  } else if (ev.kind === "threat") {
    if (action === "block") { delta = award(10); verdict = "correct block"; correct = true; }
    else if (action === "monitor") { delta = award(4); verdict = "monitored a threat"; }
    else {
      delta = award(-15);
      gameState.missed += 1;
      gameState.timeLeft = Math.max(0, gameState.timeLeft - 2);
      verdict = "missed a threat";
    }
  } else {
    if (action === "monitor") { delta = award(3); verdict = "correct monitor"; correct = true; }
    else if (action === "allow") { delta = award(-4); verdict = "allowed something suspicious"; }
    else { delta = award(-4); verdict = "blocked something plausible"; }
  }

  if (correct) correctAnswer(); else wrongAnswer();

  var cls = delta >= 0 ? "log-verdict-good" : "log-verdict-bad";
  appendLog('<span class="' + cls + '">' + verdict + " (" + (delta >= 0 ? "+" : "") + delta + ")</span>");

  gameState.current = null;
  updateHud();
  nextEvent();
}

function endGame() {
  gameState.running = false;
  clearInterval(gameState.timer);
  var over = document.getElementById("gameOver");
  var sum = document.getElementById("gameSummary");
  var controls = document.getElementById("gameControls");
  if (over) over.style.display = "block";
  if (controls) {
    document.getElementById("btnAllow").disabled = true;
    document.getElementById("btnMonitor").disabled = true;
    document.getElementById("btnBlock").disabled = true;
  }

  var rating;
  if (gameState.score >= 150 && gameState.missed === 0) rating = "Analyst of the shift.";
  else if (gameState.score >= 100) rating = "Solid detection work.";
  else if (gameState.score >= 50) rating = "Passable. Review your triage.";
  else if (gameState.score >= 0) rating = "Keep practising.";
  else rating = "You let things through. Run it again.";

  if (sum) {
    sum.textContent =
      "Final score: " + gameState.score +
      " | Missed: " + gameState.missed +
      " | Events: " + gameState.totalEvents +
      " | " + rating;
  }
}

function startGame() {
  gameState.running = true;
  gameState.score = 0;
  gameState.missed = 0;
  gameState.timeLeft = 30;
  gameState.current = null;
  gameState.combo = 0;
  gameState.comboMultiplier = 1;
  gameState.correctStreak = 0;
  gameState.totalEvents = 0;

  var log = document.getElementById("gameLog");
  if (log) log.innerHTML = "";

  var over = document.getElementById("gameOver");
  if (over) over.style.display = "none";

  ["btnAllow", "btnMonitor", "btnBlock"].forEach(function (id) {
    var b = document.getElementById(id);
    if (b) b.disabled = false;
  });

  updateHud();
  appendLog('<span class="log-verdict-good">monitor online</span>');
  nextEvent();

  gameState.timer = setInterval(function () {
    gameState.timeLeft -= 1;
    updateHud();
    if (gameState.timeLeft <= 0) endGame();
  }, 1000);
}

var techniqueList = [
  "Phishing — delivering a malicious link or attachment to gain a foothold.",
  "Subdomain enumeration — discovering hidden services under a domain.",
  "Scheduled tasks — persistence by registering a task that survives reboot.",
  "Obfuscation — encoding code so it is harder to detect.",
  "Brute force — repeatedly guessing credentials against a service.",
  "Remote services — using legitimate remote protocols to move between hosts.",
  "Exfiltration over web service — sending stolen data out through normal traffic.",
  "Data encrypted for impact — ransomware encrypting data to disrupt a target.",
  "Command and scripting interpreters — abusing shells to run attacker code.",
  "Misconfigured permissions — abusing weak file or service permissions.",
  "OSINT gathering — collecting public information about a target.",
  "Exploiting public-facing applications — abusing an exposed service vulnerability."
];

function rotateTechnique() {
  var el = document.getElementById("rotatingTechnique");
  if (!el) return;
  var pick = techniqueList[Math.floor(Math.random() * techniqueList.length)];
  el.textContent = pick;
}

function loadStats() {
  var sessions = parseInt(localStorage.getItem("cs_sessions") || "0", 10);
  var best = parseInt(localStorage.getItem("cs_best") || "0", 10);
  var sEl = document.getElementById("statSessions");
  var bEl = document.getElementById("statBest");
  if (sEl) sEl.textContent = sessions;
  if (bEl) bEl.textContent = best;
}

document.addEventListener("DOMContentLoaded", function () {
  if (document.getElementById("rotatingTechnique")) {
    rotateTechnique();
    loadStats();
  }
});

document.addEventListener("DOMContentLoaded", function () {
  if (document.getElementById("gameLog")) startGame();
});