const express = require("express");
const router = express.Router();
const assessorController = require("../controllers/assessorController");
const { assessorAuthMiddleware } = require("../middleware/authMiddleware");

router.post("/assessor/register", assessorController.createAssessor);
router.post("/assessor/login", assessorController.login);
router.get(
  "/assessor-dashboard",
  assessorAuthMiddleware,
  assessorController.dashboard
);
router.get("/assessor/auth-status", assessorController.authstatus);
router.post("/assessor/logout", assessorController.logout);
router.get(
  "/api/assessor/applicants",
  assessorAuthMiddleware,
  assessorController.fetchApplicant
);
router.get(
  "/api/assessor/applicants/:id",
  assessorAuthMiddleware,
  assessorController.fetchApplicant2
);
router.get(
  "/api/assessor/applicant-documents/:applicantId",
  assessorAuthMiddleware,
  assessorController.files
);
router.get(
  "/api/evaluations",
  assessorAuthMiddleware,
  assessorController.evaluations
);
router.post(
  "/api/evaluations",
  assessorAuthMiddleware,
  assessorController.evaluations2
);
router.post(
  "/api/evaluations/finalize",
  assessorAuthMiddleware,
  assessorController.finalize
);
router.get(
  "/api/evaluations/applicant/:applicantId",
  assessorAuthMiddleware,
  assessorController.fetchEvaluation
);

module.exports = router;
