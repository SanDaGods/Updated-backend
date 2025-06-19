const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/constants");
const path = require("path");
const fs = require("fs");
const { getNextAssessorId } = require("../utils/helpers");
const Applicant = require("../models/Applicant");
const Assessor = require("../models/Assessor");
const Evaluation = require("../models/Evaluation");
const mongoose = require("mongoose");

exports.createAssessor = async (req, res) => {
  const { email, password, fullName, expertise, assessorType } = req.body;

  try {
    if (!email || !password || !fullName || !expertise || !assessorType) {
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

    const assessorId = await getNextAssessorId();
    const existing = await Assessor.findOne({ email: email.toLowerCase() });

    if (existing) {
      return res.status(400).json({
        success: false,
        error: "Email already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAssessor = new Assessor({
      email: email.toLowerCase(),
      password: hashedPassword,
      assessorId,
      fullName,
      expertise,
      assessorType,
    });

    await newAssessor.save();

    res.status(201).json({
      success: true,
      message: "Registration successful",
      data: {
        email: newAssessor.email,
        assessorId: newAssessor.assessorId,
        fullName: newAssessor.fullName,
        expertise: newAssessor.expertise,
        assessorType: newAssessor.assessorType,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      error: "Registration failed - Server error",
    });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const assessor = await Assessor.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
    });

    if (!assessor) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    if (!assessor.isApproved) {
      return res.status(403).json({
        success: false,
        error: "Account pending admin approval",
      });
    }

    const isMatch = await bcrypt.compare(password, assessor.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    assessor.lastLogin = new Date();
    await assessor.save();

    const token = jwt.sign(
      {
        userId: assessor._id,
        role: "assessor",
        assessorId: assessor.assessorId,
        email: assessor.email,
        fullName: assessor.fullName,
        expertise: assessor.expertise,
        assessorType: assessor.assessorType,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("assessorToken", token, {
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
        assessorId: assessor.assessorId,
        email: assessor.email,
        fullName: assessor.fullName,
        expertise: assessor.expertise,
        assessorType: assessor.assessorType,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
};

exports.dashboard = async (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "frontend",
      "AssessorSide",
      "AssessorDashboard",
      "AssessorDashboard.html"
    )
  );
};

exports.authstatus = async (req, res) => {
  try {
    const token = req.cookies.assessorToken;

    if (!token) {
      return res.status(200).json({
        authenticated: false,
        message: "No token found",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const assessor = await Assessor.findOne({ _id: decoded.userId }).select(
      "-password"
    );

    if (!assessor) {
      return res.status(200).json({
        authenticated: false,
        message: "Assessor not found",
      });
    }

    res.status(200).json({
      authenticated: true,
      user: {
        _id: assessor._id,
        assessorId: assessor.assessorId,
        email: assessor.email,
        fullName: assessor.fullName,
        expertise: assessor.expertise,
        assessorType: assessor.assessorType,
        isApproved: assessor.isApproved,
        createdAt: assessor.createdAt,
        lastLogin: assessor.lastLogin,
      },
    });
  } catch (err) {
    console.error("Auth status error:", err);
    res.status(200).json({
      authenticated: false,
      message: "Invalid token",
    });
  }
};

exports.logout = async (req, res) => {
  res.clearCookie("assessorToken");
  res.json({ success: true, message: "Logged out successfully" });
};

exports.fetchApplicant = async (req, res) => {
  try {
    const assessorId = req.assessor.userId;

    const applicants = await Applicant.find({
      assignedAssessors: assessorId,
      status: "Under Assessment",
    })
      .select("applicantId personalInfo status createdAt finalScore")
      .sort({ createdAt: -1 });

    const formattedApplicants = applicants.map((applicant) => {
      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo
          ? `${applicant.personalInfo.lastname || ""}, ${
              applicant.personalInfo.firstname || ""
            }`.trim()
          : "No name provided",
        course: applicant.personalInfo?.firstPriorityCourse || "Not specified",
        applicationDate: applicant.createdAt,
        score: applicant.finalScore,
        status: applicant.status || "Under Assessment",
      };
    });

    res.status(200).json({
      success: true,
      data: formattedApplicants,
    });
  } catch (error) {
    console.error("Error fetching assigned applicants:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch assigned applicants",
    });
  }
};

exports.fetchApplicant2 = async (req, res) => {
  try {
    const applicantId = req.params.id;
    const assessorId = req.assessor.userId;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId,
    })
      .select("-password -__v")
      .populate("assignedAssessors", "assessorId fullName expertise");

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found or not assigned to you",
      });
    }

    // Ensure applicantId is included in the response
    const formattedApplicant = {
      _id: applicant._id,
      applicantId: applicant.applicantId, // This is the important line
      email: applicant.email,
      status: applicant.status,
      createdAt: applicant.createdAt,
      personalInfo: applicant.personalInfo || {},
      files: applicant.files || [],
      assignedAssessors: applicant.assignedAssessors,
      name: applicant.personalInfo
        ? `${applicant.personalInfo.firstname || ""} ${
            applicant.personalInfo.lastname || ""
          }`.trim()
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

exports.files = async (req, res) => {
  try {
    const applicantId = req.params.applicantId;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const assessorId = req.assessor.userId;
    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId,
    }).select("files personalInfo");

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found or not assigned to you",
      });
    }

    const documents = applicant.files.map((file) => ({
      name: file.name || path.basename(file.path),
      path: file.path,
      type: file.type || path.extname(file.path).substring(1).toLowerCase(),
      status: "pending",
      uploadDate: file.uploadDate || new Date(),
    }));

    res.status(200).json({
      success: true,
      data: {
        applicant: {
          name: applicant.personalInfo
            ? `${applicant.personalInfo.firstname || ""} ${
                applicant.personalInfo.lastname || ""
              }`.trim()
            : "No name provided",
          course:
            applicant.personalInfo?.firstPriorityCourse || "Not specified",
        },
        documents,
      },
    });
  } catch (error) {
    console.error("Error fetching applicant documents:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch applicant documents",
    });
  }
};

exports.evaluations = async (req, res) => {
  try {
    const { applicantId } = req.query;
    const assessorId = req.assessor.userId;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const evaluation = await Evaluation.findOne({
      applicantId,
      assessorId,
    });

    if (!evaluation) {
      return res.status(200).json({
        success: true,
        data: null,
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

exports.evaluations2 = async (req, res) => {
  try {
    const { applicantId, scores } = req.body;
    const assessorId = req.assessor.userId;

    // Validate input
    if (!applicantId || !scores) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
      });
    }

    // Calculate totals
    const totalScore =
      (scores.educationalQualification?.score || 0) +
      (scores.workExperience?.score || 0) +
      (scores.professionalAchievements?.score || 0) +
      (scores.interview?.score || 0);

    const isPassed = totalScore >= 60;

    // Create the full evaluation object
    const evaluationData = {
      assessorId: new mongoose.Types.ObjectId(assessorId),
      educationalQualification: {
        score: scores.educationalQualification?.score || 0,
        comments: scores.educationalQualification?.comments || "",
        breakdown: scores.educationalQualification?.breakdown || [],
      },
      workExperience: {
        score: scores.workExperience?.score || 0,
        comments: scores.workExperience?.comments || "",
        breakdown: scores.workExperience?.breakdown || [],
      },
      professionalAchievements: {
        score: scores.professionalAchievements?.score || 0,
        comments: scores.professionalAchievements?.comments || "",
        breakdown: scores.professionalAchievements?.breakdown || [],
      },
      interview: {
        score: scores.interview?.score || 0,
        comments: scores.interview?.comments || "",
        breakdown: scores.interview?.breakdown || [],
      },
      totalScore,
      isPassed,
      status: "draft",
      evaluatedAt: new Date(),
    };

    // Update the applicant document
    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      {
        $push: { evaluations: evaluationData },
        $set: {
          status: "Under Assessment",
          updatedAt: new Date(),
        },
      },
      { new: true }
    );

    if (!updatedApplicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Evaluation saved successfully",
      data: {
        evaluation: evaluationData,
        applicant: updatedApplicant,
      },
    });
  } catch (error) {
    console.error("Error saving evaluation:", error);
    res.status(500).json({
      success: false,
      error: "Failed to save evaluation",
      details: error.message,
    });
  }
};

exports.finalize = async (req, res) => {
  try {
    const { applicantId, comments } = req.body;
    const assessorId = req.assessor.userId;

    // Find the applicant and their most recent evaluation
    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId,
    });

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found or not assigned to you",
      });
    }

    // Get the most recent evaluation (last in the array)
    const evaluationIndex = applicant.evaluations.length - 1;
    if (evaluationIndex < 0) {
      return res.status(400).json({
        success: false,
        error: "No evaluation found to finalize",
      });
    }

    const evaluation = applicant.evaluations[evaluationIndex];

    // Calculate final status
    const newStatus =
      evaluation.totalScore >= 60 ? "Evaluated - Passed" : "Evaluated - Failed";

    // Update the evaluation in the applicant's evaluations array
    const updatedApplicant = await Applicant.findOneAndUpdate(
      {
        _id: applicantId,
        [`evaluations.${evaluationIndex}.assessorId`]: assessorId,
      },
      {
        $set: {
          status: newStatus,
          finalScore: evaluation.totalScore,
          isPassed: evaluation.isPassed,
          [`evaluations.${evaluationIndex}.status`]: "finalized",
          [`evaluations.${evaluationIndex}.finalComments`]: comments,
          [`evaluations.${evaluationIndex}.finalizedAt`]: new Date(),
        },
        $push: {
          evaluationComments: {
            assessorId: assessorId,
            comments: comments,
            date: new Date(),
            evaluationId:
              applicant.evaluations[evaluationIndex]._id ||
              new mongoose.Types.ObjectId(),
          },
        },
      },
      { new: true }
    );

    res.status(200).json({
      success: true,
      message: "Evaluation finalized successfully",
      data: updatedApplicant,
    });
  } catch (error) {
    console.error("Error finalizing evaluation:", error);
    res.status(500).json({
      success: false,
      error: "Failed to finalize evaluation",
    });
  }
};

exports.fetchEvaluation = async (req, res) => {
  try {
    const { applicantId } = req.params;
    const assessorId = req.assessor.userId;

    const evaluations = await Evaluation.find({
      applicantId,
      assessorId,
    }).sort({ finalizedAt: -1 });

    res.status(200).json({
      success: true,
      data: evaluations.length > 0 ? evaluations[0] : null,
    });
  } catch (error) {
    console.error("Error fetching applicant evaluations:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch evaluations",
    });
  }
};
