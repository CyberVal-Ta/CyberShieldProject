
// member 1 stuff
function checkPw() {
  const pw = document.getElementById("pw").value;
  const res = document.getElementById("result");
  if (!pw) { res.textContent = "Start typing..."; return; }
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["Very Weak 🔴","Weak 🟠","Okay 🟡","Strong 🟢","Very Strong 🟢"];
  res.textContent = "Strength: " + labels[score];
}


// this is for  member 2
function scanEmail() {
  const txt = document.getElementById("email").value.toLowerCase();
  const flags = [];
  if (txt.includes("urgent")) flags.push("⚠ Uses urgency language");
  if (txt.includes("click here")) flags.push("⚠ 'Click here' link");
  if (txt.includes("verify your account")) flags.push("⚠ Account verification request");
  if (/bit\.ly|tinyurl|\.ru\b/.test(txt)) flags.push("⚠ Suspicious URL shortener / domain");
  if (txt.includes("password")) flags.push("⚠ Mentions password");
  document.getElementById("report").textContent =
    flags.length ? flags.join("\n") : "✅ No obvious red flags detected (still be cautious)";
}