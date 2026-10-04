// password strength checker - runs on tools.html
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

// phishing scanner - runs on tools.html
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