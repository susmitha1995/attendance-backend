const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Enable CORS
app.use(cors({
  origin: 'https://myattendancefrontend.netlify.app', // Replace with your Netlify frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.use(bodyParser.json());

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Test the connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Database Connection Error:", err);
    return;
  }
  console.log("✅ Connected to Railway MySQL!");
  connection.release();
});

// Handle connection errors
pool.on("error", (err) => {
  console.error("❌ MySQL Pool Error:", err);
  if (err.code === "PROTOCOL_CONNECTION_LOST") {
    console.log("Reconnecting to MySQL...");
    pool.getConnection((err, connection) => {
      if (err) {
        console.error("❌ Reconnection Error:", err);
      } else {
        console.log("✅ Reconnected to MySQL!");
        connection.release();
      }
    });
  }
});

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Middleware to verify JWT token
const authenticateUser = (req, res, next) => {
  let token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ status: "error", message: "Access denied. No token provided." });
  }

  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length);
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return res.status(401).json({ status: "error", message: "Invalid token." });
  }
};

// Signup endpoint
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ status: "error", message: "Username and password are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    pool.query(query, [username, hashedPassword], (err, result) => {
      if (err) {
        console.error("Error inserting into database:", err);
        return res.status(500).json({ status: "error", message: "Database error" });
      }

      res.json({ status: "success", message: "User registered successfully" });
    });
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).json({ status: "error", message: "Internal server error" });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ status: "error", message: "Username and password are required" });
  }

  try {
    const query = "SELECT * FROM users WHERE username = ?";
    pool.query(query, [username], async (err, result) => {
      if (err) {
        console.error("Error querying database:", err);
        return res.status(500).json({ status: "error", message: "Database error" });
      }

      if (result.length === 0) {
        return res.status(401).json({ status: "error", message: "Invalid username or password" });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ status: "error", message: "Invalid username or password" });
      }

      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
      res.json({ status: "success", message: "Login successful", token });
    });
  } catch (error) {
    console.error("Error comparing passwords:", error);
    res.status(500).json({ status: "error", message: "Internal server error" });
  }
});

// Protected endpoint to mark attendance
app.post("/mark-attendance", authenticateUser, (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ status: "error", message: "Name is required" });
  }

  const date = new Date().toISOString().split("T")[0];
  const query = "INSERT INTO attendance (name, date) VALUES (?, ?)";
  pool.query(query, [name, date], (err, result) => {
    if (err) {
      console.error("❌ Error inserting into database:", err);
      return res.status(500).json({ status: "error", message: "Database error", error: err.message });
    }

    console.log("✅ Attendance recorded successfully:", result);
    res.json({ status: "success", message: "Attendance recorded" });
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});