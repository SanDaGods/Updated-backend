const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const { JWT_SECRET } = require("../config/constants");
const upload = require("../middleware/fileUpload");
const { getNextApplicantId } = require("../utils/helpers");
const Applicant = require("../models/Applicant");
const mongoose = require("mongoose");
const conn = mongoose.connection;
const multer = require("multer");
const { GridFSBucket, ObjectId } = require("mongodb");

let gfs;
conn.once("open", () => {
  gfs = new GridFSBucket(conn.db, {
    bucketName: "backupFiles",
  });
});

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Registration attempt for:", email);

    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email and password are required" });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: "Invalid email format" });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, error: "Password must be at least 8 characters" });
    }

    const existingUser = await Applicant.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ success: false, error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const applicantId = await getNextApplicantId();

    const newApplicant = new Applicant({
      email: email.toLowerCase(),
      password: hashedPassword,
      applicantId,
    });

    await newApplicant.save();
    console.log("Registration successful for:", email);

    res.status(201).json({
      success: true,
      message: "Registration successful!",
      data: {
        userId: newApplicant._id,
        applicantId: newApplicant.applicantId,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, error: "Registration failed", details: error.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const applicant = await Applicant.findOne({ email });
    if (!applicant) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, applicant.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: applicant._id, role: "applicant", email: applicant.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("applicantToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/",
    });

    res.json({
      success: true,
      message: "Login successful",
      data: {
        userId: applicant._id,
        email: applicant.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, error: "Login failed" });
  }
};
