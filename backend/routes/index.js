const express = require("express");
const fs = require("fs");
const path = require("path");
const applicantRoutes = require("./applicantRoutes");
const assessorRoutes = require("./assessorRoutes");
const adminRoutes = require("./adminRoutes");

const router = express.Router();

// Health check route
router.get("/ping", (req, res) => {
  res.json({ success: true, message: "API root is working." });
});

// Optional test endpoint
router.get("/test", (req, res) => {
  res.json({ message: "Backend working!" });
});

// API routes
router.use("/applicants", applicantRoutes);
router.use("/assessors", assessorRoutes);
router.use("/admins", adminRoutes);

// Serve uploaded PDF documents
router.get("/documents/:filename", (req, res) => {
  const filename = req.params.filename;

  if (
    !filename.endsWith(".pdf") ||
    !/^[a-zA-Z0-9_\-\.]+\.pdf$/.test(filename)
  ) {
    return res.status(400).json({ error: "Only PDF files are supported" });
  }

  const filePath = path.join(__dirname, "public", "documents", filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "File not found" });
  }

  res.setHeader("Content-Type", "application/pdf");
  res.sendFile(filePath);
});

module.exports = router;
