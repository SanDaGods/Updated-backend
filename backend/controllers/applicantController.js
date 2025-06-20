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
    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
        details: "One or more required fields were empty",
      });
    }

    // Check email format with more permissive regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      console.log("Invalid email format:", email);
      return res.status(400).json({
        success: false,
        error: "Invalid email format",
        details:'Please enter a valid email address (e.g., user@example.com). Provided: ${email}',
      });
    }
    // Check password length
    if (password.length < 8) {
      console.log("Password too short");
      return res.status(400).json({
        success: false,
        error: "Password too short",
        details: "Password must be at least 8 characters",
      });
    }

    // Check if email already exists
    const existingUser = await Applicant.findOne({
      email: email.toLowerCase(),
    });
    if (existingUser) {
      console.log("Email already exists:", email);
      return res.status(400).json({
        success: false,
        error: "Email already registered",
        details: "This email is already in use",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate applicant ID
    const applicantId = await getNextApplicantId();

    // Create new applicant
    const newApplicant = new Applicant({
      email: email.toLowerCase(),
      password: hashedPassword,
      applicantId,
    });

    // Save to database
    await newApplicant.save();
    console.log("Registration successful for:", email);

    // Successful response
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
    res.status(500).json({
      success: false,
      error: "Registration failed",
      details: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const applicant = await Applicant.findOne({ email });
    if (!applicant) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }
    const isMatch = await bcrypt.compare(password, applicant.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    const token = jwt.sign(
      {
        userId: applicant._id,
        role: "applicant",
        email: applicant.email,
      },
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
    res.status(500).json({
      success: false,
      error: "Login failed",
    });
  }
};

// Update the fileFetch function
exports.fileFetch = async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);

    const file = await conn.db.collection("backupFiles.files").findOne({
      _id: fileId,
    });

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    const downloadStream = gfs.openDownloadStream(fileId);

    res.set("Content-Type", file.contentType);
    res.set("Content-Disposition", `inline; filename="${file.filename}"`);

    downloadStream.pipe(res);

    downloadStream.on("error", (error) => {
      console.error("Error streaming file:", error);
      res.status(500).json({ error: "Error streaming file" });
    });
  } catch (error) {
    console.error("Error serving file:", error);
    res.status(500).json({ error: "Failed to serve file" });
  }
};

exports.fileDelete = async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);

    const file = await conn.db.collection("backupFiles.files").findOne({
      _id: fileId,
    });

    if (!file) {
      return res.status(404).json({
        success: false,
        error: "File not found",
      });
    }

    await gfs.delete(fileId);

    res.json({
      success: true,
      message: "File deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete file",
    });
  }
};

// Update the fileSubmit function
exports.fileSubmit = async (req, res) => {
  try {
    const userId = req.body.userId;
    const label = req.body.label || "others"; // Get the label from request

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid userId format",
      });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: "No files uploaded",
      });
    }

    // Process each file
    const uploadResults = await Promise.all(
      req.files.map(async (file) => {
        return new Promise((resolve, reject) => {
          const readStream = fs.createReadStream(file.path);
          const uploadStream = gfs.openUploadStream(file.originalname, {
            contentType: file.mimetype,
            metadata: {
              uploadDate: new Date(),
              originalName: file.originalname,
              size: file.size,
              label: label, // Use the label from request
              owner: userId,
            },
          });

          readStream.on("error", (error) => {
            fs.unlinkSync(file.path);
            reject(error);
          });

          uploadStream.on("error", (error) => {
            fs.unlinkSync(file.path);
            reject(error);
          });

          uploadStream.on("finish", () => {
            fs.unlinkSync(file.path);
            resolve({
              fileId: uploadStream.id,
              filename: file.originalname,
              size: file.size,
              contentType: file.mimetype,
              label: label,
            });
          });

          readStream.pipe(uploadStream);
        });
      })
    );

    res.json({
  success: true,
  message: `${uploadResults.length} files uploaded successfully`,
  files: uploadResults,
});

  } catch (error) {
    console.error("File upload error:", error);

    // Clean up any remaining temp files
    if (req.files) {
      req.files.forEach((file) => {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      });
    }

    res.status(500).json({
      success: false,
      error: "File upload failed",
      details: error.message,
    });
  }
};

exports.updateInfo = async (req, res) => {
  try {
    // Get the userId from the request body or form data
    const userId = req.body.userId;
    let personalInfo = req.body.personalInfo;

    // If personalInfo is a string, parse it
    if (typeof personalInfo === "string") {
      try {
        personalInfo = JSON.parse(personalInfo);
      } catch (parseError) {
        return res.status(400).json({
          success: false,
          error: "Invalid personalInfo format",
          details: parseError.message,
        });
      }
    }

    // Validate userId
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid userId format",
      });
    }

    // Basic validation of required fields
    const requiredFields = [
      "firstname",
      "lastname",
      "gender",
      "age",
      "occupation",
      "nationality",
      "civilstatus",
      "birthDate",
      "birthplace",
      "mobileNumber",
      "emailAddress",
      "country",
      "province",
      "city",
      "street",
      "zipCode",
      "firstPriorityCourse",
    ];

    const missingFields = requiredFields.filter(
      (field) => !personalInfo[field]
    );
    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
        missingFields,
      });
    }

    const updateData = {
      personalInfo: personalInfo,
      updatedAt: new Date(),
    };

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      userId,
      updateData,
      { new: true }
    ).select("-password");

    if (!updatedApplicant) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Personal information and documents updated successfully",
      data: updatedApplicant,
    });
  } catch (error) {
    console.error("Error updating personal info:", error);

    // Clean up any uploaded files if error occurred
    res.status(500).json({
      success: false,
      error: "Error updating personal info",
      details: error.message,
    });
  }
};

exports.profileId = async (req, res) => {
  try {
    const applicantId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid applicant ID",
      });
    }

    const applicant = await Applicant.findById(applicantId).select(
      "-password -__v"
    );

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found",
      });
    }

    res.status(200).json({
      success: true,
      data: applicant,
    });
  } catch (error) {
    console.error("Error fetching applicant profile:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch applicant profile",
    });
  }
};

exports.authStatus = async (req, res) => {
  try {
    const token = req.cookies.applicantToken;

    if (!token) {
      return res.status(200).json({
        authenticated: false,
        message: "No token found",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const applicant = await Applicant.findOne({ _id: decoded.userId }).select(
      "-password"
    );

    if (!applicant) {
      return res.status(200).json({
        authenticated: false,
        message: "Applicant not found",
      });
    }

    res.status(200).json({
      authenticated: true,
      user: {
        _id: applicant._id,
        email: applicant.email,
        personalInfo: applicant.personalInfo,
        files: applicant.files,
        status: applicant.status,
      },
    });
  } catch (err) {
    console.error("Applicant auth status error:", err);
    res.status(200).json({
      authenticated: false,
      message: "Invalid token",
    });
  }
};

exports.logout = async (req, res) => {
  res.clearCookie("applicantToken");
  res.json({ success: true, message: "Logged out successfully" });
};

exports.fetchUserFiles = async (req, res) => {
  try {
    const userId = req.params.userId;
    console.log("Fetching files for user:", userId); // Debug log

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      console.log("Invalid user ID:", userId); // Debug log
      return res.status(400).json({
        success: false,
        error: "Invalid user ID format",
      });
    }

    const files = await conn.db
      .collection("backupFiles.files")
      .find({
        "metadata.owner": userId,
      })
      .toArray();

    console.log("Files found:", files.length); // Debug log

    const groupedFiles = files.reduce((acc, file) => {
      const label = file.metadata?.label || "others";
      if (!acc[label]) {
        acc[label] = [];
      }
      acc[label].push({
        _id: file._id,
        filename: file.filename,
        contentType: file.contentType,
        uploadDate: file.uploadDate,
        size: file.metadata?.size,
        label: label,
      });
      return acc;
    }, {});

    console.log("Grouped files:", Object.keys(groupedFiles)); // Debug log

    res.json({
      success: true,
      files: groupedFiles,
    });
  } catch (error) {
    console.error("Error fetching user files:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch files",
      details: error.message,
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const userId = req.body.userId;
    const updateData = JSON.parse(req.body.data);

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ success: false, error: "Invalid user ID" });
    }

    // Handle profile picture upload if present
    if (req.file) {
      const uploadStream = gfs.openUploadStream("profile-pic-" + userId, {
        contentType: req.file.mimetype,
        metadata: {
          userId: userId,
          type: "profile-pic",
        },
      });

      // Delete old profile picture if exists
      const oldPic = await conn.db.collection("backupFiles.files").findOne({
        "metadata.userId": userId,
        "metadata.type": "profile-pic",
      });

      if (oldPic) {
        await gfs.delete(oldPic._id);
      }

      // Upload new picture
      fs.createReadStream(req.file.path)
        .pipe(uploadStream)
        .on("error", (error) => {
          console.error("Error uploading profile pic:", error);
        })
        .on("finish", () => {
          fs.unlinkSync(req.file.path);
        });

      updateData.profilePicId = uploadStream.id;
    }

    // Update user data
    const result = await Applicant.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true }
    );

    if (!result) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: result,
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update profile",
    });
  }
};

exports.getProfilePic = async (req, res) => {
  try {
    const userId = req.params.userId;

    const file = await conn.db.collection("backupFiles.files").findOne({
      "metadata.userId": userId,
      "metadata.type": "profile-pic",
    });

    if (!file) {
      return res.status(404).send("No profile picture found");
    }

    const downloadStream = gfs.openDownloadStream(file._id);
    res.set("Content-Type", file.contentType);
    downloadStream.pipe(res);
  } catch (error) {
    console.error("Error serving profile pic:", error);
    res.status(500).send("Error retrieving profile picture");
}
};
