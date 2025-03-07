const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");

const app = express();

// Enable CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://127.0.0.1:5500"); // Allow requests from this origin
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"); // Allow these methods
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization"); // Allow these headers
  next();
});

app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Replace with your MySQL username
  password: "Sus$2121", // Replace with your MySQL password
  database: "attendance_db",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// API to mark attendance
app.post("/mark-attendance", (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ status: "error", message: "Name is required" });
  }

  const date = new Date().toISOString().split("T")[0]; // Get current date in YYYY-MM-DD format

  const query = "INSERT INTO attendance (name, date) VALUES (?, ?)";
  db.query(query, [name, date], (err, result) => {
    if (err) {
      console.error("Error inserting into database:", err);
      return res.status(500).json({ status: "error", message: "Database error" });
    }

    res.json({ status: "success", message: "Attendance recorded" });
  });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});