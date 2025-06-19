require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const connectDB = require("./config/db");
const { PORT } = require("./config/constants");
const routes = require("./routes");
const applicants = require("./routes/applicantRoutes");
const admins = require("./routes/adminRoutes");
const assessors = require("./routes/assessorRoutes");

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());

// ✅ CORS: Allow your frontend URLs
app.use(
  cors({
    origin: [
      "https://updated-frontend-ten.vercel.app", // <-- your Vercel frontend
      "http://localhost:3000",                   // <-- for local testing
    ],
    credentials: true,
    exposedHeaders: ["set-cookie"],
  })
);

// ✅ Do NOT serve static frontend files (Vercel handles that)
/// Removed: app.use(express.static(path.join(__dirname, "frontend")));


// ✅ Routes
app.use("/", routes, applicants, assessors, admins);

// ✅ Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    success: false,
    error: "Internal server error",
    details: process.env.NODE_ENV === "production" ? undefined : err.message,
  });
});

// ✅ Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
