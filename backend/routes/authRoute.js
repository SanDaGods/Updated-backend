const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

// POST /api/register
router.post("/register", authController.register);

// ADD THIS: POST /api/login
router.post("/login", authController.login);

// Optional: Ping test route
router.get("/ping", (req, res) => {
  res.json({ success: true, message: "Ping successful" });
});

module.exports = router;
