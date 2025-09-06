ยอดเยี่ยม — เดี๋ยวผมอัปเกรด Rock77 ให้รองรับ JWT (JSON Web Token) เพื่อให้การล็อกอิน/เรียก API ปลอดภัยขึ้น โดยสิ่งที่จะได้คือ:

รหัสผ่านยังถูก เข้ารหัสด้วย bcrypt ก่อนเก็บใน MySQL

เมื่อล็อกอินสำเร็จ backend จะคืน JWT ให้ frontend

Frontend เก็บ token (ในตัวอย่างใช้ localStorage) และส่ง Authorization: Bearer <token> ตอนเรียก API ที่ป้องกันด้วย token

มี middleware ตรวจสอบ token (verify) ใน backend เพื่อป้องกันการเข้าถึง endpoint ที่ต้องล็อกอินเท่านั้น


ด้านล่างเป็นโค้ดตัวอย่างครบ พร้อมคำอธิบายวิธีตั้งค่า — ทำตามขั้นตอนแล้วรันได้เลย


---

1) ติดตั้ง dependencies (backend)

ไปที่โฟลเดอร์ backend แล้วรัน:

npm init -y
npm install express mysql2 body-parser cors bcrypt jsonwebtoken dotenv

> ถ้าใช้ Node แบบ ES modules ให้ใส่ "type": "module" ใน package.json (หรือแปลงเป็น require แบบ CommonJS ได้ตามชอบ)



สร้างไฟล์ .env ใน backend/:

DB_HOST=localhost
DB_USER=root
DB_PASS=your_mysql_password
DB_NAME=rock77
JWT_SECRET=changeme_to_a_long_random_secret
JWT_EXPIRES_IN=2h
PORT=3000


---

2) โค้ด backend/server.js (Node.js + Express + MySQL + bcrypt + JWT)

// backend/server.js
import express from "express";
import mysql from "mysql2";
import bodyParser from "body-parser";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "rock77",
});

db.connect(err => {
  if (err) {
    console.error("❌ MySQL connect error:", err);
    process.exit(1);
  }
  console.log("✅ MySQL connected");
});

// Helper: generate JWT
function generateToken(user) {
  const payload = { id: user.id, username: user.username };
  const secret = process.env.JWT_SECRET || "your_jwt_secret";
  const expiresIn = process.env.JWT_EXPIRES_IN || "2h";
  return jwt.sign(payload, secret, { expiresIn });
}

// Middleware: verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader) return res.status(401).json({ success:false, message: "No token provided" });

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ success:false, message: "Token format invalid" });
  }

  const token = parts[1];
  jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret", (err, decoded) => {
    if (err) return res.status(401).json({ success:false, message: "Token invalid or expired" });
    req.user = decoded; // { id, username, iat, exp }
    next();
  });
}

// Signup (hash password)
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("กรุณาใส่ username และ password");

  db.query("SELECT id FROM users WHERE username = ?", [username], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length > 0) return res.status(400).send("มีชื่อผู้ใช้นี้แล้ว");

    try {
      const hashed = await bcrypt.hash(password, 10);
      db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed], (err2) => {
        if (err2) return res.status(500).send("Database insert error");
        res.send("🎉 สมัครสมาชิกสำเร็จ");
      });
    } catch (e) {
      res.status(500).send("Server error");
    }
  });
});

// Login -> return JWT
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("กรุณาใส่ username และ password");

  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(401).send("ไม่พบผู้ใช้");

    const user = result[0]; // user.password is hashed
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send("รหัสผ่านไม่ถูกต้อง");

    const token = generateToken({ id: user.id, username: user.username });
    res.json({ success: true, message: "เข้าสู่ระบบสำเร็จ", token, username: user.username });
  });
});

// Protected route example: get profile
app.get("/profile", verifyToken, (req, res) => {
  // req.user from token
  res.json({ success: true, profile: { id: req.user.id, username: req.user.username } });
});

// Logout (optional client-side only) - server does not need to do anything unless you blacklist tokens

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});


---

3) ปรับ frontend/script.js (เก็บ token, ส่ง Authorization header, แสดงสถานะ)

// frontend/script.js
const API_URL = "http://localhost:3000";

// เก็บ token และ username ใน localStorage
function setLogin(token, username) {
  localStorage.setItem("rock77_token", token);
  localStorage.setItem("rock77_user", username);
  updateLoginStatus();
}

function logout() {
  localStorage.removeItem("rock77_token");
  localStorage.removeItem("rock77_user");
  updateLoginStatus();
}

function getToken() {
  return localStorage.getItem("rock77_token");
}

function updateLoginStatus() {
  const user = localStorage.getItem("rock77_user");
  const statusEl = document.getElementById("loginStatus");
  if (user) {
    statusEl.innerText = `👋 สวัสดี, ${user}`;
  } else {
    statusEl.innerText = "❌ ยังไม่ได้เข้าสู่ระบบ";
  }
}

window.onload = () => {
  updateLoginStatus();
};

// Signup (calls backend)
async function handleSignUp() {
  const user = document.getElementById("signUser").value;
  const pass = document.getElementById("signPass").value;
  if(!user || !pass) return alert("กรุณากรอกชื่อผู้ใช้และรหัสผ่าน");

  try {
    const res = await fetch(`${API_URL}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: user, password: pass })
    });
    const text = await res.text();
    alert(text);
    if (res.ok) closeModal("signUpModal");
  } catch (err) {
    alert("Error: " + err);
  }
}

// Login -> รับ token
async function handleLogin() {
  const user = document.getElementById("loginUser").value;
  const pass = document.getElementById("loginPass").value;
  if(!user || !pass) return alert("กรุณากรอกชื่อผู้ใช้และรหัสผ่าน");

  try {
    const res = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: user, password: pass })
    });

    // ถ้าส่ง JSON (success) หรือ text (error) ให้รองรับทั้งสอง
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await res.json();
      if (res.ok && data.token) {
        setLogin(data.token, data.username);
        alert(data.message || "เข้าสู่ระบบสำเร็จ");
        closeModal("loginModal");
      } else {
        alert(data.message || "Login failed");
      }
    } else {
      const txt = await res.text();
      alert(txt);
    }
  } catch (err) {
    alert("Error: " + err);
  }
}

// ตัวอย่างเรียก API ที่ต้องใช้ token
async function fetchProfile() {
  const token = getToken();
  if (!token) return alert("กรุณาเข้าสู่ระบบก่อน");

  try {
    const res = await fetch(`${API_URL}/profile`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      }
    });

    const data = await res.json();
    if (res.ok) {
      alert("Profile: " + JSON.stringify(data.profile));
    } else {
      alert(data.message || "ไม่สามารถเรียกข้อมูลได้");
      if (res.status === 401) {
        // token อาจหมดอายุ -> ออกจากระบบ
        logout();
      }
    }
  } catch (err) {
    alert("Error: " + err);
  }
}

อย่าลืมเพิ่มปุ่ม/อินเตอร์เฟสใน index.html:

<div id="loginStatus">❌ ยังไม่ได้เข้าสู่ระบบ</div>
<button onclick="logout()">ออกจากระบบ</button>
<button onclick="fetchProfile()">เรียกข้อมูลโปรไฟล์ (ต้องล็อกอิน)</button>


---

4) สร้างตาราง MySQL (ถ้ายังไม่ได้สร้าง)

CREATE DATABASE rock77;
USE rock77;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);


---

5) รันทดสอบ

1. สตาร์ท backend:



cd backend
node server.js

2. เปิด frontend/index.html ในเบราว์เซอร์ (หรือเสิร์ฟผ่าน simple server เช่น npx serve ถ้าต้องการ CORS ถูกต้อง)


3. สมัครสมาชิก → ล็อกอิน → จะได้ token แล้วหน้าเว็บจะแสดงสถานะผู้ใช้


4. กดปุ่ม เรียกข้อมูลโปรไฟล์ เพื่อทดสอบเรียก /profile ด้วย token




---

หมายเหตุด้านความปลอดภัย (สำคัญ)

อย่าเก็บ JWT_SECRET ไว้เป็นค่าในโค้ด — ให้เก็บใน .env / secret manager ของเซิร์ฟเวอร์

ในโปรดักชัน ต้องใช้ HTTPS เพื่อป้องกัน token ถูกดักจับ (man-in-the-middle)

พิจารณาเก็บ token แบบ safer (เช่น HttpOnly cookie) แทน localStorage ถ้ากังวล XSS

ตั้ง JWT_EXPIRES_IN ให้พอเหมาะ และพิจารณา logout/blacklist token หากต้องการยกเลิกสิทธิ์ก่อนหมดอายุ

รหัสผ่านต้องเข้ารหัสด้วย bcrypt (เราใช้แล้ว) และถ้าระดับองค์กร ควรมี rate-limiting / account lockout เพื่อป้องกัน brute-force



---

ถ้าต้องการ ผมสามารถ:

ให้โค้ดไฟล์ทั้งหมดเป็นไฟล์ให้ดาวน์โหลด (zip)

เปลี่ยนให้เก็บ token เป็น HttpOnly cookie แบบตัวอย่าง (ปลอดภัยกว่า localStorage)

ใส่ refresh token และ flow การต่ออายุ token (access + refresh tokens)

เซ็ตตัวอย่าง Docker Compose ให้รัน MySQL + node server อัตโนมัติ


อยากให้ผมทำข้อไหนต่อเลยครับ?


