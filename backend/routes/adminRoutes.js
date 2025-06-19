const express = require("express");
const router = express.Router();
const adminController = require("../controllers/adminController");
const { adminAuthMiddleware } = require("../middleware/authMiddleware");

router.post("/admin/register", adminController.createAdmin);
router.post("/admin/login", adminController.login);
router.get("/admin/auth-status", adminController.authstatus);
router.post("/admin/logout", adminController.logout);
router.get("/admin/dashboard", adminAuthMiddleware, adminController.dashboard);
router.get(
  "/api/admin/applicants",
  adminAuthMiddleware,
  adminController.fetchApplicant
);
router.get(
  "/api/admin/applicants/:id",
  adminAuthMiddleware,
  adminController.fetchApplicantInfo
);
router.post(
  "/api/admin/applicants/:id/approve",
  adminAuthMiddleware,
  adminController.approveApplicant
);
router.post(
  "/api/admin/applicants/:id/reject",
  adminAuthMiddleware,
  adminController.disapproveApplicant
);
router.post(
  "/api/admin/applicants/:id/assign-assessor",
  adminAuthMiddleware,
  adminController.assignAssessor
);
router.get(
  "/api/admin/available-assessors",
  adminAuthMiddleware,
  adminController.availableAsessor
);
router.get(
  "/api/admin/dashboard-stats",
  adminAuthMiddleware,
  adminController.dashboard
);
router.post(
  "/assessor/all",
  adminAuthMiddleware,
  adminController.getallAssessor
);
router.get(
  "/assessor/:id",
  adminAuthMiddleware,
  adminController.getAssessorInfo
);
router.put(
  "/assessor/:id",
  adminAuthMiddleware,
  adminController.updateAssessor
);
router.delete(
  "/assessor/:id",
  adminAuthMiddleware,
  adminController.deleteAssessor
);
router.get(
  "/api/assessor/:id/applicants",
  adminAuthMiddleware,
  adminController.fetchAssessorApplicants
);
router.get(
  "/api/admin/evaluations",
  adminAuthMiddleware,
  adminController.fetchEvaluation
);
router.get(
  "/api/admin/evaluations/:id",
  adminAuthMiddleware,
  adminController.fetchEvaluationID
);
router.get(
  "/api/admin/admins",
  adminAuthMiddleware,
  adminController.fetchAdmins
);
router.get(
  "/api/admin/admins/:id",
  adminAuthMiddleware,
  adminController.fetchAdminID
);
router.put(
  "/api/admin/admins/:id",
  adminAuthMiddleware,
  adminController.updateAdmin
);
router.delete(
  "/api/admin/admins/:id",
  adminAuthMiddleware,
  adminController.deleteAdmin
);
router.put(
  "/api/admin/admins/:id/change-password",
  adminAuthMiddleware,
  adminController.changepassAdmin
);

module.exports = router;
