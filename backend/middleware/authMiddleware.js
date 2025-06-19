const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/constants");
const Applicant = require("../models/Applicant");
const Assessor = require("../models/Assessor");
const Admin = require("../models/Admin");

const applicantAuthMiddleware = async (req, res, next) => {
  const token = req.cookies.applicantToken;

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.applicant = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

const assessorAuthMiddleware = async (req, res, next) => {
  const token = req.cookies.assessorToken;

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.assessor = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

const adminAuthMiddleware = async (req, res, next) => {
  const token = req.cookies.adminToken;

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

module.exports = {
  applicantAuthMiddleware,
  assessorAuthMiddleware,
  adminAuthMiddleware,
};
