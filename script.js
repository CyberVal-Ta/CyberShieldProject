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