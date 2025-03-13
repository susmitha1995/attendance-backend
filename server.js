const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config(); // Load environment variables from .env file
const app = express();

// Enable CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // Allow requests from any origin (update this in production)
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"); // Allow these methods
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization"); // Allow these headers
  next();
});

app.use(bodyParser.json());





// MySQL connection configuration using Railway variables
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,       // Use Railway MySQL host
  user: process.env.MYSQLUSER,       // Use Railway MySQL user
  password: process.env.MYSQLPASSWORD, // Use Railway MySQL password
  database: process.env.MYSQLDATABASE, // Use Railway MySQL database
  port: process.env.MYSQLPORT || 3306, // Default to 3306 if not set
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database Connection Error:", err);
    return;
  }
  console.log("✅ Connected to Railway MySQL!");
});


// Secret key for JWT (keep this secure in production)
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Middleware to verify JWT token
const authenticateUser = (req, res, next) => {
  let token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ status: "error", message: "Access denied. No token provided." });
  }

  // Remove "Bearer " prefix if present
  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length); // Remove "Bearer " (7 characters)
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Attach user data to the request
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
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(query, [username, hashedPassword], (err, result) => {
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
    // Fetch user from the database
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], async (err, result) => {
      if (err) {
        console.error("Error querying database:", err);
        return res.status(500).json({ status: "error", message: "Database error" });
      }

      if (result.length === 0) {
        return res.status(401).json({ status: "error", message: "Invalid username or password" });
      }

      // Compare passwords
      const user = result[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ status: "error", message: "Invalid username or password" });
      }

      // Generate a JWT token
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });

      // Return the token in the response
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

  const date = new Date().toISOString().split("T")[0]; // Get current date in YYYY-MM-DD format

  const query = "INSERT INTO attendance (name, date) VALUES (?, ?)";
  db.query(query, [name, date], (err, result) => {
    if (err) {
      console.error("❌ Error inserting into database:", err); // Log the error in console
      return res.status(500).json({ status: "error", message: "Database error", error: err.message });
    }

    console.log("✅ Attendance recorded successfully:", result);
    res.json({ status: "success", message: "Attendance recorded" });
  });
});

// Start the server
const PORT = process.env.PORT || 3000; // Use environment variable or fallback to 3000
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});