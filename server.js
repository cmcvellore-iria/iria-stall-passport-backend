const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "iria-secret-key";

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ================== IN-MEMORY STORE ================== */
const users = {};        // email -> { name, email, passwordHash, visits:Set }
const approvedEmails = new Set();
try {
  const csv = fs.readFileSync("registered_emails.csv", "utf8");
  csv.split(/\r?\n/).forEach(line => {
    const email = line.trim().toLowerCase();
    if (email) approvedEmails.add(email);
  });
  console.log("Loaded", approvedEmails.size, "approved emails");
} catch (e) {
  console.error("Failed to load registered_emails.csv");
}

const visitTokens = {};  // token -> { stall, exp }

/* ================== HELPERS ================== */
function signToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.email = decoded.email;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

/* ================== AUTH ================== */
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const cleanEmail = email.toLowerCase().trim();

  // ✅ Email must exist in uploaded registration list
  if (!approvedEmails.has(cleanEmail)) {
    return res.status(403).json({
      error: "Email not found in conference registration list"
    });
  }

  // ✅ Prevent duplicate accounts
  if (users[cleanEmail]) {
    return res.status(400).json({ error: "User already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  users[cleanEmail] = {
    name,
    email: cleanEmail,
    passwordHash,
    visits: new Set()
  };

  res.json({
    token: signToken(cleanEmail),
    name
  });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  res.json({
    token: signToken(email),
    name: user.name
  });
});

/* ================== VISITS ================== */
app.get("/api/visits", auth, (req, res) => {
  const user = users[req.email];
  res.json({ visits: [...user.visits] });
});

app.post("/api/generate-visit-token", auth, (req, res) => {
  const { stall } = req.body;
  if (!stall) return res.status(400).json({ error: "Missing stall" });

  const token = Math.random().toString(36).slice(2);
  const exp = Date.now() + 2 * 60 * 1000;

  visitTokens[token] = { stall, exp };
  res.json({ token, exp });
});

app.post("/api/verify", auth, (req, res) => {
  const { token, stall } = req.body;
  const data = visitTokens[token];

  if (!data || data.exp < Date.now() || data.stall != stall)
    return res.status(400).json({ error: "Invalid token" });

  // prevent duplicate stall visit
if (users[req.email].visits.has(Number(stall))) {
  return res.status(400).json({ error: "Stall already recorded" });
}
  users[req.email].visits.add(Number(stall));
  delete visitTokens[token];

  res.json({ ok: true });
});

/* ================== LEADERBOARD ================== */
app.get("/api/leaderboard", (req, res) => {
  const top = Object.values(users)
    .map(u => ({ name: u.name, count: u.visits.size }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  res.json({ top });
});

app.post("/api/admin/reset", (req, res) => {
  const key = req.headers["admin-key"];
  if (key !== "iriaadminreset") {
    return res.status(403).json({ error: "Forbidden" });
  }

  Object.values(users).forEach(u => u.visits.clear());
  Object.keys(visitTokens).forEach(k => delete visitTokens[k]);

  res.json({ ok: true });
});

app.get("/api/admin/export", (req, res) => {
  const key = req.headers["admin-key"] || req.query.key;
  if (key !== "iriaadminreset") {
    return res.status(403).json({ error: "Forbidden" });
  }

  let csv = "Name,Email,Visited_Count,Visited_Stalls\n";

  Object.values(users).forEach(u => {
    const stalls = [...u.visits].join(" ");
    csv += `"${u.name}","${u.email}",${u.visits.size},"${stalls}"\n`;
  });

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=iria_stall_passport.csv");
  res.send(csv);
});

/* ================== ROOT ================== */
app.get("/", (_, res) => {
  res.send("IRIA Stall Passport Backend Running");
});

app.listen(PORT, () =>
  console.log("Backend listening on", PORT)
);
