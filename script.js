// password strength checker - used on password.html
function checkPw() {
  const pw = document.getElementById("pw").value;
  const res = document.getElementById("result");
  if (!res) return;                         // bail if not on that page
  if (!pw) { res.textContent = "Start typing..."; return; }

  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const labels = ["Very Weak 🔴", "Weak 🟠", "Okay 🟡", "Strong 🟢", "Very Strong 🟢"];
  res.textContent = "Strength: " + labels[score];
}

// phishing scanner - used on phishing.html
function scanEmail() {
  const el = document.getElementById("email");
  const report = document.getElementById("report");
  if (!el || !report) return;

  const txt = el.value.toLowerCase();
  const flags = [];
  if (txt.includes("urgent")) flags.push("⚠ Uses urgency language");
  if (txt.includes("click here")) flags.push("⚠ 'Click here' link");
  if (txt.includes("verify your account")) flags.push("⚠ Account verification request");
  if (/bit\.ly|tinyurl|\.ru\b/.test(txt)) flags.push("⚠ Suspicious URL shortener / domain");
  if (txt.includes("password")) flags.push("⚠ Mentions password");

  report.textContent = flags.length
    ? flags.join("\n")
    : "✅ No obvious red flags detected (still be cautious)";
}

// live activity feed on index.html - just flavour
function startActivityFeed() {
  const feed = document.getElementById("activityFeed");
  if (!feed) return;   // not on homepage, skip

  const events = [
    "Port scan detected from 10.0.4.22 — blocked",
    "MFA challenge passed for user j.smith",
    "Failed login attempt on admin account",
    "Firewall rules updated",
    "Suspicious email quarantined",
    "Password policy audit completed",
    "Endpoint flagged for outbound traffic spike",
    "VPN session established from 203.0.113.9",
    "Log rotation completed",
    "Threat intelligence feed synchronised"
  ];

  // random interval between 3-7 sec
  setInterval(() => {
    const li = document.createElement("li");
    const msg = events[Math.floor(Math.random() * events.length)];
    const t = new Date().toLocaleTimeString();
    li.textContent = `[${t}] ${msg}`;
    feed.prepend(li);   // newest at top

    // keep list short
    while (feed.children.length > 15) {
      feed.removeChild(feed.lastChild);
    }
  }, 4000);
}

// kick off whichever page we're on
document.addEventListener("DOMContentLoaded", startActivityFeed);