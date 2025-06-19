const express = require("express");
const path = require("path");
const fs = require("fs");
const applicantRoutes = require("./applicantRoutes");
const assessorRoutes = require("./assessorRoutes");
const adminRoutes = require("./adminRoutes");

const router = express.Router();

router.use(express.static(path.join(__dirname, "../../frontend")));
router.use(express.static(path.join(__dirname, "../../frontend/client")));
router.use(
  express.static(path.join(__dirname, "../../frontend/client/applicant"))
);
router.use(
  express.static(path.join(__dirname, "../../frontend/client/applicant/home"))
);
router.use(
  express.static(path.join(__dirname, "../../frontend/client/applicant/login"))
);

router.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../../frontend/client/applicant/home/index.html")
  );
});

router.get("/applicant-login", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../../frontend/client/applicant/login/login.html")
  );
});

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
