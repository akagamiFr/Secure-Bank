const express = require('express');
const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors());
// ------------------------------------------------------------------

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret';
const DB_CONFIG = {
  user: process.env.PGUSER || 'postgres',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'secure_bank',
  password: process.env.PGPASSWORD || '123945',
  port: process.env.PGPORT ? parseInt(process.env.PGPORT) : 5432,
};
// Uploads directory (will be created if missing)
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,9) + ext);
  }
});
const upload = multer({ storage });
// ---------------------------

// ---------- DATABASE ----------
const db = new Client(DB_CONFIG);

async function initDb() {
  await db.connect();
  console.log('Connected to PostgreSQL');

  // create tables if not exist
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      monthly_income NUMERIC,
      date_of_birth DATE,
      address TEXT,
      nid_picture TEXT,
      balance NUMERIC DEFAULT 50000,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS loans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC NOT NULL,
      status VARCHAR(50) DEFAULT 'active',
      taken_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      paid_at TIMESTAMP
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS cards (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      card_number VARCHAR(40),
      card_type VARCHAR(50),
      expiry DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255),
      role VARCHAR(100),
      email VARCHAR(255)
    );
  `);

  // seed employees if empty
  const emp = await db.query('SELECT COUNT(*) FROM employees');
  if (parseInt(emp.rows[0].count) === 0) {
    await db.query(`
      INSERT INTO employees (name, role, email) VALUES
        ('Mr. Rahim Ahmed','Manager','rahim@efportal.com'),
        ('Ms. Jahanara Khatun','Customer Support','jahanara@efportal.com'),
        ('Mr. Shakil Hossain','Loan Officer','shakil@efportal.com')
    `);
  }

  console.log('DB initialized');
}

initDb().catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
// ---------------------------

// ---------- AUTH HELPERS ----------
function verifyJwt(token) {
  return jwt.verify(token, JWT_SECRET);
}

async function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ success: false, message: 'Authorization header missing' });
    const token = auth.replace(/^Bearer\s+/, '');
    let decoded;
    try {
      decoded = verifyJwt(token);
    } catch (e) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    const q = await db.query('SELECT id, name, email, monthly_income, balance, address, nid_picture FROM users WHERE id=$1', [decoded.id]);
    if (q.rows.length === 0) return res.status(401).json({ success: false, message: 'User not found' });

    req.user = q.rows[0];
    next();
  } catch (err) {
    console.error('Auth middleware error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
}
// ----------------------------------

// Serve uploads
app.use('/uploads', express.static(UPLOADS_DIR));

// ----------------- API ROUTES -----------------

// Signup (JSON)
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, income, dob, address } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Missing required fields' });

    const exists = await db.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length > 0) return res.status(400).json({ success: false, message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (name, email, password, monthly_income, date_of_birth, address)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [name, email, hashed, income || null, dob || null, address || null]
    );

    res.status(201).json({ success: true, message: 'Account created successfully' });
  } catch (err) {
    console.error('Signup error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Signup with file (multipart)
app.post('/api/signup-with-file', upload.single('nidImage'), async (req, res) => {
  try {
    const { name, email, password, income, dob, address } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Missing required fields' });

    const exists = await db.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length > 0) return res.status(400).json({ success: false, message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const nidPath = req.file ? '/uploads/' + req.file.filename : null;

    await db.query(
      `INSERT INTO users (name, email, password, monthly_income, date_of_birth, address, nid_picture)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [name, email, hashed, income || null, dob || null, address || null, nidPath]
    );

    res.status(201).json({ success: true, message: 'Account created successfully' });
  } catch (err) {
    console.error('Signup-with-file error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Signin -> return JWT
app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Missing credentials' });

    const q = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    if (q.rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid email or password' });

    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    const safeUser = { id: user.id, name: user.name, email: user.email, monthly_income: user.monthly_income, balance: user.balance, nid_picture: user.nid_picture };

    res.json({ success: true, message: 'Login successful', user: safeUser, token });
  } catch (err) {
    console.error('Signin error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get user info
app.get('/api/user', authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});

// Take loan
app.post('/api/user/take-loan', authMiddleware, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount) return res.status(400).json({ success: false, message: 'Missing amount' });

    const ur = await db.query('SELECT monthly_income, balance FROM users WHERE id=$1', [req.user.id]);
    const user = ur.rows[0];
    const maxLoan = (user.monthly_income || 0) * 3;
    const amt = parseFloat(amount);
    if (amt > maxLoan) return res.status(400).json({ success: false, message: `Maximum loan based on income is ${maxLoan}` });

    await db.query('INSERT INTO loans (user_id, amount, status) VALUES ($1,$2,$3)', [req.user.id, amt, 'active']);
    const newBalance = parseFloat(user.balance || 0) + amt;
    await db.query('UPDATE users SET balance=$1 WHERE id=$2', [newBalance, req.user.id]);

    res.status(201).json({ success: true, message: 'Loan approved', newBalance });
  } catch (err) {
    console.error('Take loan error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Loan history
app.get('/api/user/loans', authMiddleware, async (req, res) => {
  try {
    const lr = await db.query('SELECT * FROM loans WHERE user_id=$1 ORDER BY taken_at DESC', [req.user.id]);
    res.json({ success: true, loans: lr.rows });
  } catch (err) {
    console.error('Loan history error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Change password
app.post('/api/user/change-password', authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: 'Missing passwords' });

  // Need to fetch hashed password
  const q = await db.query('SELECT password FROM users WHERE id=$1', [req.user.id]);
  const ok = await bcrypt.compare(oldPassword, q.rows[0].password);
  if (!ok) return res.status(401).json({ success: false, message: 'Incorrect old password' });

  const hashed = await bcrypt.hash(newPassword, 10);
  await db.query('UPDATE users SET password=$1 WHERE id=$2', [hashed, req.user.id]);

  res.json({ success: true, message: 'Password changed successfully' });
} catch (err) {
  console.error('Change password error', err);
  res.status(500).json({ success: false, message: 'Server error' });
}
});

// Cards
app.get('/api/cards', authMiddleware, async (req, res) => {
  try {
    const cr = await db.query('SELECT * FROM cards WHERE user_id=$1', [req.user.id]);
    res.json({ success: true, cards: cr.rows });
  } catch (err) {
    console.error('Cards error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Employees list
app.get('/api/employees', async (req, res) => {
  try {
    const er = await db.query('SELECT id, name, role, email FROM employees ORDER BY id');
    res.json({ success: true, employees: er.rows });
  } catch (err) {
    console.error('Employees error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
const frontendHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Secure Bank</title>

  <style>
    * {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  color: #333;
  line-height: 1.6;
  animation: gradientShift 15s ease infinite;
  background-size: 200% 200%;
}

@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

#header-title {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  padding: 1.5rem 2rem;
  text-align: center;
  font-size: 2rem;
  font-weight: 700;
  color: #667eea;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
  animation: slideDown 0.6s ease-out;
  border-bottom: 3px solid #667eea;
}

@keyframes slideDown {
  from {
    transform: translateY(-100%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

nav {
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  padding: 1rem 2rem;
  display: flex;
  justify-content: center;
  gap: 1rem;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
  animation: fadeIn 0.8s ease-out 0.2s both;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

nav a {
  color: #667eea;
  text-decoration: none;
  padding: 0.6rem 1.5rem;
  border-radius: 25px;
  font-weight: 600;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

nav a::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
  transition: left 0.5s ease;
}

nav a:hover::before {
  left: 100%;
}

nav a:hover {
  background: #667eea;
  color: white;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.hidden {
  display: none !important;
}

.container {
  max-width: 1200px;
  margin: 2rem auto;
  padding: 0 1.5rem;
  animation: fadeInUp 0.8s ease-out 0.4s both;
}

@keyframes fadeInUp {
  from {
    transform: translateY(30px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

.card {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  border-radius: 20px;
  padding: 2rem;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12);
  margin-bottom: 2rem;
  animation: cardEntrance 0.6s ease-out;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

@keyframes cardEntrance {
  from {
    transform: scale(0.95);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
}

.card:hover {
  transform: translateY(-5px);
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
}

.card h2 {
  color: #667eea;
  margin-bottom: 1.5rem;
  font-size: 1.8rem;
  position: relative;
  display: inline-block;
}

.card h2::after {
  content: '';
  position: absolute;
  bottom: -8px;
  left: 0;
  width: 0;
  height: 3px;
  background: linear-gradient(90deg, #667eea, #764ba2);
  animation: underlineExpand 0.8s ease-out 0.3s forwards;
}

@keyframes underlineExpand {
  to { width: 100%; }
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 2rem;
  margin-top: 1.5rem;
}

.grid > div {
  background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
  padding: 1.5rem;
  border-radius: 15px;
  animation: scaleIn 0.5s ease-out;
  transition: transform 0.3s ease;
}

@keyframes scaleIn {
  from {
    transform: scale(0.8);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
}

.grid > div:hover {
  transform: scale(1.03);
}

form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

input, button {
  padding: 0.9rem 1.2rem;
  border-radius: 12px;
  border: 2px solid transparent;
  font-size: 1rem;
  transition: all 0.3s ease;
  animation: inputSlide 0.5s ease-out backwards;
}

@keyframes inputSlide {
  from {
    transform: translateX(-20px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

input:nth-child(1) { animation-delay: 0.1s; }
input:nth-child(2) { animation-delay: 0.2s; }
input:nth-child(3) { animation-delay: 0.3s; }
input:nth-child(4) { animation-delay: 0.4s; }
input:nth-child(5) { animation-delay: 0.5s; }
input:nth-child(6) { animation-delay: 0.6s; }

input {
  border-color: #e0e0e0;
  background: white;
}

input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  transform: translateY(-2px);
}

button {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-weight: 600;
  cursor: pointer;
  border: none;
  position: relative;
  overflow: hidden;
  animation: buttonPulse 0.6s ease-out 0.5s backwards;
}

@keyframes buttonPulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.05); }
}

button::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 0;
  height: 0;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.3);
  transform: translate(-50%, -50%);
  transition: width 0.6s ease, height 0.6s ease;
}

button:hover::before {
  width: 300px;
  height: 300px;
}

button:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
}

button:active {
  transform: translateY(-1px);
  box-shadow: 0 4px 10px rgba(102, 126, 234, 0.3);
}

hr {
  border: none;
  height: 2px;
  background: linear-gradient(90deg, transparent, #667eea, transparent);
  margin: 2rem 0;
  animation: hrExpand 1s ease-out;
}

@keyframes hrExpand {
  from { transform: scaleX(0); }
  to { transform: scaleX(1); }
}

#loan-history-list > div,
#cards-list > div {
  background: linear-gradient(135deg, #f5f7fa 0%, #e4e9f2 100%);
  padding: 1rem;
  margin-bottom: 0.8rem;
  border-radius: 12px;
  animation: listItemSlide 0.4s ease-out backwards;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  border-left: 4px solid #667eea;
}

@keyframes listItemSlide {
  from {
    transform: translateX(-30px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

#loan-history-list > div:nth-child(1) { animation-delay: 0.1s; }
#loan-history-list > div:nth-child(2) { animation-delay: 0.2s; }
#loan-history-list > div:nth-child(3) { animation-delay: 0.3s; }
#loan-history-list > div:nth-child(4) { animation-delay: 0.4s; }

#cards-list > div:nth-child(1) { animation-delay: 0.1s; }
#cards-list > div:nth-child(2) { animation-delay: 0.2s; }
#cards-list > div:nth-child(3) { animation-delay: 0.3s; }

#loan-history-list > div:hover,
#cards-list > div:hover {
  transform: translateX(10px);
  box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
}

#balance-page h1 {
  color: #667eea;
  font-size: 3.5rem;
  margin-top: 1rem;
  animation: balanceCount 1s ease-out;
}

@keyframes balanceCount {
  from {
    transform: scale(0.5);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
}

footer {
  text-align: center;
  padding: 2rem;
  color: white;
  background: rgba(0, 0, 0, 0.2);
  backdrop-filter: blur(10px);
  margin-top: 3rem;
  animation: fadeIn 1s ease-out 0.8s both;
  font-weight: 500;
}

label {
  color: #555;
  font-weight: 600;
  animation: fadeIn 0.5s ease-out;
}

p {
  animation: fadeIn 0.6s ease-out;
}

strong {
  color: #667eea;
}

@media (max-width: 768px) {
  #header-title {
    font-size: 1.5rem;
    padding: 1rem;
  }

  nav {
    flex-wrap: wrap;
    gap: 0.5rem;
    padding: 1rem;
  }

  nav a {
    padding: 0.5rem 1rem;
    font-size: 0.9rem;
  }

  .container {
    padding: 0 1rem;
    margin: 1rem auto;
  }

  .card {
    padding: 1.5rem;
  }

  .grid {
    grid-template-columns: 1fr;
    gap: 1rem;
  }

  #balance-page h1 {
    font-size: 2.5rem;
  }
}

/* Floating animation for the home page */
#home-page .card {
  animation: float 3s ease-in-out infinite;
}

@keyframes float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-10px); }
}

/* Shimmer effect for cards */
.card::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
  transition: left 0.7s ease;
  pointer-events: none;
}

.card:hover::before {
  left: 100%;
}

/* Pulse animation for important elements */
#user-balance, #balance-amount {
  display: inline-block;
  animation: pulse 2s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.05); }
}
  </style>
</head>

<body>
  <header id="header-title">Secure Bank </header>

  <!-- PUBLIC NAV -->
  <nav id="main-nav">
    <a href="/home" onclick="showPage('home'); return false;">Home</a>
    <a href="/login" onclick="showPage('login'); return false;">Login</a>
  </nav>

  <!-- LOGGED-IN NAV -->
  <nav id="dashboard-nav" class="hidden">
    <a href="/dashboard" onclick="showPage('dashboard'); return false;">Dashboard</a>
    <a href="/take-loan" onclick="showPage('take-loan'); return false;">Take Loan</a>
    <a href="/loan-history" onclick="showPage('loan-history'); return false;">Loan History</a>
    <a href="/cards" onclick="showPage('cards'); return false;">Cards</a>
    <a href="/balance" onclick="showPage('balance'); return false;">Balance</a>
    <a href="/change-password" onclick="showPage('change-password'); return false;">Change Password</a>
    <a href="/login" onclick="logoutUser(); return false;">Logout</a>
  </nav>

  <main class="container">

    <!-- HOME -->
    <section id="home-page">
      <div class="card">
        <h2>Welcome</h2>
        <p>Manage your finances — check balance, take loans, manage cards.</p>
      </div>
    </section>

    <!-- LOGIN / SIGNUP -->
    <section id="login-page" class="hidden">
      <div class="card" style="max-width:520px;margin:auto;">
        <h2>Sign In</h2>
        <form id="signin-form">
          <input id="signin-email" type="email" placeholder="Email" required />
          <input id="signin-password" type="password" placeholder="Password" required />
          <button type="submit">Sign In</button>
        </form>

        <hr style="margin:1rem 0;">

        <h2>Create Account</h2>
        <form id="signup-form" enctype="multipart/form-data">
          <input id="name" type="text" placeholder="Full name" required />
          <input id="email" type="email" placeholder="Email" required />
          <input id="password" type="password" placeholder="Password" required />
          <input id="income" type="number" placeholder="Monthly income" />
          <input id="dob" type="date" />
          <input id="address" type="text" placeholder="Address" />
          <label style="display:block;margin-top:.6rem;">Upload NID (optional)</label>
          <input id="nid" type="file" accept="image/*" />
          <button type="submit">Sign Up</button>
        </form>
      </div>
    </section>

    <!-- DASHBOARD -->
    <section id="dashboard-page" class="hidden">
      <div class="card">
        <h2>Dashboard</h2>
        <div class="grid">
          <div>
            <p><strong>Name:</strong> <span id="user-name">-</span></p>
            <p><strong>Email:</strong> <span id="user-email">-</span></p>
            <p><strong>Monthly Income:</strong> <span id="user-income">-</span></p>
          </div>
          <div>
            <p><strong>Balance:</strong> ৳<span id="user-balance">0</span></p>
            <p><strong>Last Loan:</strong> <span id="loan-summary">-</span></p>
          </div>
        </div>
      </div>
    </section>
    <section id="take-loan-page" class="hidden">
      <div class="card" style="max-width:450px;margin:auto;">
        <h2>Take Loan</h2>
        <form id="take-loan-form">
          <input id="loan-amount" type="number" placeholder="Loan amount" required />
          <button type="submit">Apply</button>
        </form>
      </div>
    </section>

    <!-- LOAN HISTORY -->
    <section id="loan-history-page" class="hidden">
      <div class="card">
        <h2>Loan History</h2>
        <div id="loan-history-list"></div>
      </div>
    </section>

    <!-- CARDS -->
    <section id="cards-page" class="hidden">
      <div class="card">
        <h2>Your Cards</h2>
        <div id="cards-list"></div>
      </div>
    </section>

    <!-- BALANCE -->
    <section id="balance-page" class="hidden">
      <div class="card">
        <h2>Balance</h2>
        <p>Your Current Balance:</p>
        <h1>৳<span id="balance-amount">0</span></h1>
      </div>
    </section>

    <!-- CHANGE PASSWORD -->
    <section id="change-password-page" class="hidden">
      <div class="card" style="max-width:450px;margin:auto;">
        <h2>Change Password</h2>
        <form id="change-password-form">
          <input id="old-password" type="password" placeholder="Old password" required />
          <input id="new-password" type="password" placeholder="New password" required />
          <button type="submit">Update</button>
        </form>
      </div>
    </section>
  </main>

  <footer>© 2024 Secure Bank</footer>

  <script>
    const tokenKey = 'efp_token';
    let currentUser = null;

    // Hide all pages
    function hideAllPages() {
      document.querySelectorAll('main section').forEach(sec => sec.classList.add('hidden'));
    }

    // Show a page + update navigation
    function showPage(page) {
      history.pushState({}, '', '/' + page);
      hideAllPages();

      const publicNav = document.getElementById("main-nav");
      const dashNav = document.getElementById("dashboard-nav");
      const headerTitle = document.getElementById("header-title");

      if (!localStorage.getItem(tokenKey)) {
        publicNav.classList.remove('hidden');
        dashNav.classList.add('hidden');
        headerTitle.textContent = "Secure Bank";

        if (page === 'login') {
          document.getElementById('login-page').classList.remove('hidden');
        } else {
          document.getElementById('home-page').classList.remove('hidden');
        }
        return;
      }

      // logged in
      publicNav.classList.add('hidden');
      dashNav.classList.remove('hidden');

      if (page === 'dashboard') {
        loadDashboard();
        document.getElementById('dashboard-page').classList.remove('hidden');
        headerTitle.textContent = "Dashboard";
      }
      else if (page === 'take-loan') {
        document.getElementById('take-loan-page').classList.remove('hidden');
        headerTitle.textContent = "Take Loan";
      }
      else if (page === 'loan-history') {
        loadLoanHistory();
        document.getElementById('loan-history-page').classList.remove('hidden');
        headerTitle.textContent = "Loan History";
      }
      else if (page === 'cards') {
        loadCards();
        document.getElementById('cards-page').classList.remove('hidden');
        headerTitle.textContent = "Cards";
      }
      else if (page === 'balance') {
        loadBalance();
        document.getElementById('balance-page').classList.remove('hidden');
        headerTitle.textContent = "Balance";
      }
      else if (page === 'change-password') {
        document.getElementById('change-password-page').classList.remove('hidden');
        headerTitle.textContent = "Change Password";
      }
      else {
        // fallback
        document.getElementById('dashboard-page').classList.remove('hidden');
        headerTitle.textContent = "Dashboard";
      }
    }

    // Auto-load correct page on back/forward
    window.onpopstate = () => {
      const path = window.location.pathname.replace('/', '') || 'home';
      showPage(path);
    };

    // ---------------- AUTH ----------------
    async function autoLogin() {
      const token = localStorage.getItem(tokenKey);
      if (!token) {
        showPage('home');
        return;
      }
      try {
        const res = await fetch('/api/user', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (!data.success) {
          localStorage.removeItem(tokenKey);
          showPage('login');
          return;
        }
        currentUser = data.user;
        showPage('dashboard');
      } catch (err) {
        console.error('Auto-login error', err);
        showPage('login');
      }
    }

    // SIGNIN
    document.getElementById('signin-form').addEventListener('submit', async e => {
      e.preventDefault();
      const email = document.getElementById('signin-email').value;
      const password = document.getElementById('signin-password').value;

      try {
        const res = await fetch('/api/signin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!data.success) return alert(data.message);

        localStorage.setItem(tokenKey, data.token);
        currentUser = data.user;
        showPage('dashboard');
      } catch (err) {
        console.error('signin error', err);
      }
    });

    // SIGNUP
    document.getElementById('signup-form').addEventListener('submit', async e => {
      e.preventDefault();
      const formData = new FormData();
      formData.append('name', document.getElementById('name').value);
      formData.append('email', document.getElementById('email').value);
      formData.append('password', document.getElementById('password').value);
      formData.append('income', document.getElementById('income').value);
      formData.append('dob', document.getElementById('dob').value);
      formData.append('address', document.getElementById('address').value);
      const nidFile = document.getElementById('nid').files[0];
      if (nidFile) formData.append('nidImage', nidFile);

      try {
        const res = await fetch('/api/signup-with-file', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) showPage('login');
      } catch (err) {
        console.error('signup error', err);
      }
    });

    // LOGOUT
    function logoutUser() {
      localStorage.removeItem(tokenKey);
      currentUser = null;
      showPage('home');
    }

    // ---------------- LOADERS ----------------

    async function loadDashboard() {
      try {
        const res = await fetch('/api/user', {
          headers: { 'Authorization': 'Bearer ' + localStorage.getItem(tokenKey) }
        });
        const data = await res.json();
        if (!data.success) return;

        currentUser = data.user;
        document.getElementById('user-name').textContent = currentUser.name;
        document.getElementById('user-email').textContent = currentUser.email;
        document.getElementById('user-income').textContent = currentUser.monthly_income || 0;
        document.getElementById('user-balance').textContent = currentUser.balance || 0;

      } catch (err) {
        console.error('dashboard error', err);
      }
    }

    async function loadBalance() {
      if (!currentUser) return;
      document.getElementById('balance-amount').textContent = currentUser.balance;
    }

    async function loadLoanHistory() {
  try {
    const res = await fetch('/api/user/loans', {
      headers: { 'Authorization': 'Bearer ' + localStorage.getItem(tokenKey) }
    });
    const data = await res.json();
    if (!data.success) return;

    const list = document.getElementById('loan-history-list');

    list.innerHTML = data.loans.map(l => {
      return (
        '<div style="padding:.6rem;border-bottom:1px solid #eee">' +
          '<strong>৳' + l.amount + '</strong> — ' + l.status +
          '<div style="font-size:.85rem;color:#666">' +
            new Date(l.taken_at).toLocaleString() +
          '</div>' +
        '</div>'
      );
    }).join('');

  } catch (err) {
    console.error('loan history error', err);
  }
}

   async function loadCards() {
  try {
    const res = await fetch('/api/cards', {
      headers: { 'Authorization': 'Bearer ' + localStorage.getItem(tokenKey) }
    });
    const data = await res.json();
    if (!data.success) return;

    const list = document.getElementById('cards-list');

    if (data.cards.length === 0) {
      list.innerHTML = '<p>No cards found</p>';
      return;
    }

    list.innerHTML = data.cards.map(c => {
      return (
        '<div style="padding:.6rem;border-bottom:1px solid #ddd">' +
          '<strong>' + c.card_type + '</strong><br>' +
          'Card No: ' + c.card_number + '<br>' +
          'Expiry: ' + c.expiry +
        '</div>'
      );
    }).join('');

  } catch (err) {
    console.error('cards error', err);
  }
}

    // TAKE LOAN
    document.getElementById('take-loan-form').addEventListener('submit', async e => {
      e.preventDefault();
      const amount = document.getElementById('loan-amount').value;

      try {
        const res = await fetch('/api/user/take-loan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem(tokenKey)
          },
          body: JSON.stringify({ amount })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) {
          currentUser.balance = data.newBalance;
          showPage('balance');
        }
      } catch (err) {
        console.error('take loan error', err);
      }
    });

    // CHANGE PASSWORD
    document.getElementById('change-password-form').addEventListener('submit', async e => {
      e.preventDefault();
      const oldPassword = document.getElementById('old-password').value;
      const newPassword = document.getElementById('new-password').value;

      try {
        const res = await fetch('/api/user/change-password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem(tokenKey)
          },
          body: JSON.stringify({ oldPassword, newPassword })
        });

        const data = await res.json();
        alert(data.message);
        if (data.success) showPage('dashboard');
      } catch (err) {
        console.error('change pw error', err);
      }
    });

    // Start app
    autoLogin();
  </script>

</body>
</html>`;
app.get(/^\/(?!api).*/, (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(frontendHTML);
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
