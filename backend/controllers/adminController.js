const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const { JWT_SECRET } = require("../config/constants");
const mongoose = require("mongoose");

const Admin = require("../models/Admin");
const Applicant = require("../models/Applicant");
const Assessor = require("../models/Assessor");
const Evaluation = require("../models/Evaluation");
const { getNextApplicantId, getNextAssessorId } = require("../utils/helpers");

exports.createAdmin = async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password || !fullName) {
      return res.status(400).json({
        success: false,
        error: "All fields are required",
      });
    }

    if (password.length < 8 || password.length > 16) {
      return res.status(400).json({
        success: false,
        error: "Password must be 8-16 characters",
      });
    }

    const adminCount = await Admin.countDocuments();
    let isSuperAdmin = false;

    if (adminCount > 0) {
      const token = req.cookies.adminToken;

      if (!token) {
        return res.status(401).json({
          success: false,
          error: "Authentication required - please login first",
        });
      }

      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const requestingAdmin = await Admin.findById(decoded.userId);

        if (!requestingAdmin || !requestingAdmin.isSuperAdmin) {
          return res.status(403).json({
            success: false,
            error: "Only super admins can register new admins",
          });
        }
      } catch (err) {
        return res.status(401).json({
          success: false,
          error: "Invalid authentication token",
        });
      }
    } else {
      isSuperAdmin = true;
    }

    const existing = await Admin.findOne({ email: email.toLowerCase() });

    if (existing) {
      return res.status(400).json({
        success: false,
        error: "Email already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({
      email: email.toLowerCase(),
      password: hashedPassword,
      fullName,
      isSuperAdmin,
    });

    await newAdmin.save();

    return res.status(201).json({
      success: true,
      message: "Admin registration successful. Please login.",
      redirectTo: "/login/login.html",
      data: {
        email: newAdmin.email,
        fullName: newAdmin.fullName,
        isSuperAdmin: newAdmin.isSuperAdmin,
        createdAt: newAdmin.createdAt,
      },
    });
  } catch (error) {
    console.error("Admin registration error:", error);
    return res.status(500).json({
      success: false,
      error: "Admin registration failed - Server error",
    });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
    });

    if (!admin) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      {
        userId: admin._id,
        role: "admin",
        email: admin.email,
        fullName: admin.fullName,
        isSuperAdmin: admin.isSuperAdmin,
      },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.cookie("adminToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 28800000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/",
    });

    res.json({
      success: true,
      message: "Login successful",
      redirectTo: "/client/admin/dashboard/dashboard.html",
      data: {
        email: admin.email,
        fullName: admin.fullName,
        isSuperAdmin: admin.isSuperAdmin,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
};

exports.authstatus = async (req, res) => {
  try {
    const token = req.cookies.adminToken;

    if (!token) {
      return res.status(200).json({
        authenticated: false,
        message: "No token found",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findOne({ _id: decoded.userId }).select(
      "-password"
    );

    if (!admin) {
      return res.status(200).json({
        authenticated: false,
        message: "Admin not found",
      });
    }

    res.status(200).json({
      authenticated: true,
      user: {
        _id: admin._id,
        email: admin.email,
        fullName: admin.fullName,
        isSuperAdmin: admin.isSuperAdmin,
        createdAt: admin.createdAt,
        lastLogin: admin.lastLogin,
      },
    });
  } catch (err) {
    console.error("Admin auth status error:", err);
    res.status(200).json({
      authenticated: false,
      message: "Invalid token",
    });
  }
};

exports.logout = async (req, res) => {
  res.clearCookie("adminToken");
  res.json({ success: true, message: "Admin logged out successfully" });
};

exports.dashboard = (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "frontend",
      "client",
      "admin",
      "dashboard",
      "dashboard.html"
    )
  );
};

exports.fetchApplicant = async (req, res) => {
  try {
    // Remove the limit parameter to always return all applicants
    const applicants = await Applicant.find({})
      .select("-password -files -__v")
      .sort({ createdAt: -1 });

    const formattedApplicants = applicants.map((applicant) => {
      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo
          ? `${applicant.personalInfo.lastname || ""}, 
               ${applicant.personalInfo.firstname || ""} 
              ${applicant.personalInfo.middlename || ""}`.trim()
          : "No name provided",
        course: applicant.personalInfo?.firstPriorityCourse || "Not specified",
        applicationDate: applicant.createdAt || new Date(),
        currentScore: applicant.finalScore || 0,
        status: applicant.status || "Pending Review",
      };
    });

    res.status(200).json({
      success: true,
      data: formattedApplicants,
    });
  } catch (error) {
    console.error("Error fetching applicants:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch applicants",
    });
  }
};

exports.fetchApplicantInfo = async (req, res) => {
  try {
    const applicantId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const applicant = await Applicant.findById(applicantId)
      .select("-password -__v")
      .populate("assignedAssessors", "assessorId fullName expertise")
      .populate("evaluations");

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    const formattedApplicant = {
      _id: applicant._id,
      applicantId: applicant.applicantId,
      email: applicant.email,
      status: applicant.status,
      createdAt: applicant.createdAt,
      personalInfo: applicant.personalInfo,
      files: applicant.files,
      assignedAssessors: applicant.assignedAssessors,
      evaluations: applicant.evaluations,
      finalScore: applicant.finalScore,
      isPassed: applicant.isPassed,
      name: applicant.personalInfo
        ? `${applicant.personalInfo.lastname || ""}, ${
            applicant.personalInfo.firstname || ""
          } ${applicant.personalInfo.middlename || ""}`.trim()
        : "No name provided",
      course: applicant.personalInfo?.firstPriorityCourse || "Not specified",
    };

    res.status(200).json({
      success: true,
      data: formattedApplicant,
    });
  } catch (error) {
    console.error("Error fetching applicant:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch applicant",
    });
  }
};

exports.approveApplicant = async (req, res) => {
  try {
    const applicantId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      { status: "Approved" },
      { new: true }
    ).select("-password -files -__v");

    if (!updatedApplicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Applicant approved successfully",
      data: updatedApplicant,
    });
  } catch (error) {
    console.error("Error approving applicant:", error);
    res.status(500).json({
      success: false,
      error: "Failed to approve applicant",
    });
  }
};

exports.disapproveApplicant = async (req, res) => {
  try {
    const applicantId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      { status: "Rejected" },
      { new: true }
    ).select("-password -files -__v");

    if (!updatedApplicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Applicant rejected successfully",
      data: updatedApplicant,
    });
  } catch (error) {
    console.error("Error rejecting applicant:", error);
    res.status(500).json({
      success: false,
      error: "Failed to reject applicant",
    });
  }
};

exports.assignAssessor = async (req, res) => {
  try {
    const { applicantId, assessorId } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(applicantId) ||
      !mongoose.Types.ObjectId.isValid(assessorId)
    ) {
      return res.status(400).json({
        success: false,
        error: "Invalid IDs provided",
      });
    }

    const [applicant, assessor] = await Promise.all([
      Applicant.findById(applicantId),
      Assessor.findById(assessorId),
    ]);

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    if (!assessor || !assessor.isApproved) {
      return res.status(400).json({
        success: false,
        error: "Assessor not found or not approved",
      });
    }

    // Get applicant details for the assignment record
    const applicantFullName = applicant.personalInfo
      ? `${applicant.personalInfo.firstname || ""} ${
          applicant.personalInfo.lastname || ""
        }`.trim()
      : "No name provided";
    const applicantCourse =
      applicant.personalInfo?.firstPriorityCourse || "Not specified";

    // Update both documents
    const [updatedApplicant, updatedAssessor] = await Promise.all([
      Applicant.findByIdAndUpdate(
        applicantId,
        {
          status: "Under Assessment",
          $addToSet: { assignedAssessors: assessorId },
        },
        { new: true }
      ).select("-password -__v"),

      Assessor.findByIdAndUpdate(
        assessorId,
        {
          $addToSet: {
            assignedApplicants: {
              applicantId: applicant._id,
              fullName: applicantFullName,
              course: applicantCourse,
              status: "Under Assessment",
            },
          },
        },
        { new: true }
      ).select("-password -__v"),
    ]);

    res.status(200).json({
      success: true,
      message: "Assessor assigned successfully",
      data: {
        applicant: updatedApplicant,
        assessor: {
          _id: assessor._id,
          assessorId: assessor.assessorId,
          fullName: assessor.fullName,
          assignedApplicants: updatedAssessor.assignedApplicants,
        },
      },
    });
  } catch (error) {
    console.error("Error assigning assessor:", error);
    res.status(500).json({
      success: false,
      error: "Failed to assign assessor",
      details: error.message,
    });
  }
};

exports.availableAsessor = async (req, res) => {
  try {
    const assessors = await Assessor.find({ isApproved: true })
      .select("_id assessorId fullName expertise assessorType")
      .sort({ fullName: 1 });

    res.status(200).json({
      success: true,
      data: assessors,
    });
  } catch (error) {
    console.error("Error fetching assessors:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch assessors",
    });
  }
};

exports.dashboard = async (req, res) => {
  try {
    const totalApplicants = await Applicant.countDocuments();
    const newApplicants = await Applicant.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    });
    const pendingReview = await Applicant.countDocuments({
      status: "Pending Review",
    });
    const underAssessment = await Applicant.countDocuments({
      status: "Under Assessment",
    });
    const evaluatedPassed = await Applicant.countDocuments({
      status: "Evaluated - Passed",
    });
    const evaluatedFailed = await Applicant.countDocuments({
      status: "Evaluated - Failed",
    });
    const rejected = await Applicant.countDocuments({ status: "Rejected" });

    res.status(200).json({
      success: true,
      data: {
        totalApplicants,
        newApplicants,
        pendingReview,
        underAssessment,
        evaluatedPassed,
        evaluatedFailed,
        rejected,
      },
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch dashboard stats",
    });
  }
};

exports.getallAssessor = async (req, res) => {
  try {
    const assessors = await Assessor.find({})
      .populate("assignedApplicants")
      .select("-password -__v")
      .sort({ createdAt: -1 });

    const formattedAssessors = assessors.map((assessor) => ({
      ...assessor.toObject(),
      applicantsCount: assessor.assignedApplicants.length,
      assignedApplicants: assessor.assignedApplicants.map((applicant) => ({
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo
          ? `${applicant.personalInfo.lastname || ""}, ${
              applicant.personalInfo.firstname || ""
            }`.trim()
          : "No name provided",
        status: applicant.status || "Under Assessment",
      })),
    }));

    res.status(200).json({
      success: true,
      data: formattedAssessors,
    });
  } catch (error) {
    console.error("Error fetching assessors:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch assessors",
    });
  }
};

exports.getAssessorInfo = async (req, res) => {
  try {
    const assessor = await Assessor.findById(req.params.id)
      .select("-password -__v")
      .populate({
        path: "assignedApplicants.applicantId",
        select: "applicantId personalInfo status files evaluations",
        model: "Applicant",
      });

    if (!assessor) {
      return res.status(404).json({
        success: false,
        error: "Assessor not found",
      });
    }

    // Format the response with complete applicant data
    const formattedAssessor = {
      ...assessor.toObject(),
      assignedApplicants: assessor.assignedApplicants.map((assignment) => {
        const applicant = assignment.applicantId || {};
        return {
          _id: applicant._id || assignment.applicantId,
          applicantId: applicant.applicantId || "N/A",
          fullName: applicant.personalInfo
            ? `${applicant.personalInfo.lastname || ""}, ${
                applicant.personalInfo.firstname || ""
              }`.trim()
            : assignment.fullName || "No name provided",
          course:
            applicant.personalInfo?.firstPriorityCourse ||
            assignment.course ||
            "Not specified",
          dateAssigned: assignment.dateAssigned,
          status: applicant.status || assignment.status || "Under Assessment",
        };
      }),
    };

    res.status(200).json({
      success: true,
      data: formattedAssessor,
    });
  } catch (error) {
    console.error("Error fetching assessor:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch assessor",
      details: error.message,
    });
  }
};

exports.updateAssessor = async (req, res) => {
  try {
    const { fullName, email, assessorType, expertise, isApproved } = req.body;

    const updatedAssessor = await Assessor.findByIdAndUpdate(
      req.params.id,
      { fullName, email, assessorType, expertise, isApproved },
      { new: true, runValidators: true }
    ).select("-password -__v");

    if (!updatedAssessor) {
      return res.status(404).json({
        success: false,
        error: "Assessor not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Assessor updated successfully",
      data: updatedAssessor,
    });
  } catch (error) {
    console.error("Error updating assessor:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update assessor",
    });
  }
};

exports.deleteAssessor = async (req, res) => {
  try {
    const deletedAssessor = await Assessor.findByIdAndDelete(req.params.id);

    if (!deletedAssessor) {
      return res.status(404).json({
        success: false,
        error: "Assessor not found",
      });
    }

    // Remove this assessor from any assigned applicants
    await Applicant.updateMany(
      { assignedAssessors: deletedAssessor._id },
      { $pull: { assignedAssessors: deletedAssessor._id } }
    );

    res.status(200).json({
      success: true,
      message: "Assessor deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting assessor:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete assessor",
    });
  }
};

exports.fetchAssessorApplicants = async (req, res) => {
  try {
    const assessor = await Assessor.findById(req.params.id)
      .populate(
        "assignedApplicants",
        "applicantId personalInfo status files evaluations"
      )
      .select("assignedApplicants");

    if (!assessor) {
      return res.status(404).json({
        success: false,
        error: "Assessor not found",
      });
    }

    const formattedApplicants = assessor.assignedApplicants.map((applicant) => {
      const latestEvaluation =
        applicant.evaluations && applicant.evaluations.length > 0
          ? applicant.evaluations[applicant.evaluations.length - 1]
          : null;

      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo
          ? `${applicant.personalInfo.lastname || ""}, ${
              applicant.personalInfo.firstname || ""
            }`.trim()
          : "No name provided",
        course: applicant.personalInfo?.firstPriorityCourse || "Not specified",
        status: applicant.status || "Under Assessment",
        documentsCount: applicant.files ? applicant.files.length : 0,
        latestScore: latestEvaluation ? latestEvaluation.totalScore : null,
        isPassed: latestEvaluation ? latestEvaluation.isPassed : null,
      };
    });

    res.status(200).json({
      success: true,
      data: formattedApplicants,
    });
  } catch (error) {
    console.error("Error fetching assessor applicants:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch assessor applicants",
    });
  }
};

exports.fetchEvaluation = async (req, res) => {
  try {
    const evaluations = await Evaluation.find({})
      .populate("applicantId", "personalInfo status")
      .populate("assessorId", "assessorId fullName expertise")
      .sort({ finalizedAt: -1 });

    const formattedEvaluations = evaluations.map((eval) => {
      const applicant = eval.applicantId;
      const assessor = eval.assessorId;

      return {
        _id: eval._id,
        applicantId: applicant._id,
        applicantName: applicant.personalInfo
          ? `${applicant.personalInfo.lastname}, ${applicant.personalInfo.firstname}`
          : "No name provided",
        applicantCourse:
          applicant.personalInfo?.firstPriorityCourse || "Not specified",
        assessorId: assessor._id,
        assessorName: assessor.fullName,
        assessorExpertise: assessor.expertise,
        totalScore: eval.totalScore,
        isPassed: eval.isPassed,
        status: eval.status,
        evaluatedAt: eval.evaluatedAt,
        finalizedAt: eval.finalizedAt,
      };
    });

    res.status(200).json({
      success: true,
      data: formattedEvaluations,
    });
  } catch (error) {
    console.error("Error fetching evaluations:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch evaluations",
    });
  }
};
exports.fetchEvaluationID = async (req, res) => {
  try {
    const evaluation = await Evaluation.findById(req.params.id)
      .populate("applicantId", "personalInfo files status")
      .populate("assessorId", "assessorId fullName expertise assessorType");

    if (!evaluation) {
      return res.status(404).json({
        success: false,
        error: "Evaluation not found",
      });
    }

    res.status(200).json({
      success: true,
      data: evaluation,
    });
  } catch (error) {
    console.error("Error fetching evaluation:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch evaluation",
    });
  }
};

exports.fetchAdmins = async (req, res) => {
  try {
    const requestingAdmin = await Admin.findById(req.admin.userId);

    if (!requestingAdmin.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - Only super admins can access this resource",
      });
    }

    const admins = await Admin.find({})
      .select("-password -__v")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: admins,
    });
  } catch (error) {
    console.error("Error fetching admins:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch admins",
    });
  }
};

exports.fetchAdminID = async (req, res) => {
  try {
    const requestingAdmin = await Admin.findById(req.admin.userId);
    const adminId = req.params.id;

    // Only super admins can view other admin details
    if (
      !requestingAdmin.isSuperAdmin &&
      requestingAdmin._id.toString() !== adminId
    ) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - You can only view your own profile",
      });
    }

    const admin = await Admin.findById(adminId).select("-password -__v");

    if (!admin) {
      return res.status(404).json({
        success: false,
        error: "Admin not found",
      });
    }
    res.status(200).json({
      success: true,
      data: admin,
    });
  } catch (error) {
    console.error("Error fetching admin:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch admin",
    });
  }
};

exports.updateAdmin = async (req, res) => {
  try {
    const requestingAdmin = await Admin.findById(req.admin.userId);
    const adminId = req.params.id;
    const { fullName, email, isSuperAdmin } = req.body;

    // Only super admins can modify other admins
    if (
      !requestingAdmin.isSuperAdmin &&
      requestingAdmin._id.toString() !== adminId
    ) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - You can only modify your own profile",
      });
    }

    // Only super admins can change super admin status
    if (isSuperAdmin !== undefined && !requestingAdmin.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - Only super admins can change admin privileges",
      });
    }

    const updateData = { fullName, email };
    if (isSuperAdmin !== undefined && requestingAdmin.isSuperAdmin) {
      updateData.isSuperAdmin = isSuperAdmin;
    }
    const updatedAdmin = await Admin.findByIdAndUpdate(adminId, updateData, {
      new: true,
      runValidators: true,
    }).select("-password -__v");

    if (!updatedAdmin) {
      return res.status(404).json({
        success: false,
        error: "Admin not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Admin updated successfully",
      data: updatedAdmin,
    });
  } catch (error) {
    console.error("Error updating admin:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update admin",
    });
  }
};

exports.deleteAdmin = async (req, res) => {
  try {
    const requestingAdmin = await Admin.findById(req.admin.userId);
    const adminId = req.params.id;

    if (!requestingAdmin.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - Only super admins can delete admins",
      });
    }

    // Prevent self-deletion
    if (requestingAdmin._id.toString() === adminId) {
      return res.status(400).json({
        success: false,
        error: "Cannot delete your own account",
      });
    }

    const adminCount = await Admin.countDocuments({ isSuperAdmin: true });
    const targetAdmin = await Admin.findById(adminId);

    // Prevent deleting the last super admin
    if (targetAdmin.isSuperAdmin && adminCount <= 1) {
      return res.status(400).json({
        success: false,
        error: "Cannot delete the last super admin",
      });
    }

    const deletedAdmin = await Admin.findByIdAndDelete(adminId);

    if (!deletedAdmin) {
      return res.status(404).json({
        success: false,
        error: "Admin not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Admin deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting admin:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete admin",
    });
  }
};

exports.changepassAdmin = async (req, res) => {
  try {
    const requestingAdmin = await Admin.findById(req.admin.userId);
    const adminId = req.params.id;
    const { currentPassword, newPassword } = req.body;

    // Only super admins or the account owner can change password
    if (
      !requestingAdmin.isSuperAdmin &&
      requestingAdmin._id.toString() !== adminId
    ) {
      return res.status(403).json({
        success: false,
        error: "Unauthorized - You can only change your own password",
      });
    }

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "New password must be at least 8 characters",
      });
    }

    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({
        success: false,
        error: "Admin not found",
      });
    }

    // Verify current password for non-super admin requests
    if (
      !requestingAdmin.isSuperAdmin ||
      requestingAdmin._id.toString() === adminId
    ) {
      const isMatch = await bcrypt.compare(currentPassword, admin.password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          error: "Current password is incorrect",
        });
      }
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({
      success: false,
      error: "Failed to change password",
    });
  }
};
