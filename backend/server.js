require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");
const { GridFSBucket } = require("mongodb");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { ObjectId } = require("mongodb");
const PORT = process.env.PORT || 3000;

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: [
      "https://updated-frontend-ten.vercel.app", // Production frontend
      "http://localhost:3000",                   // Local dev
    ],
    credentials: true,
    exposedHeaders: ["set-cookie"],
  })
);

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI;
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
    process.exit(1); // exit if database fails
  }
};

connectDB();

connectDB();

const conn = mongoose.connection;
let gfs;

conn.once("open", async () => {
  console.log("✅ MongoDB connected successfully");
  gfs = new GridFSBucket(conn.db, { bucketName: "applicantFiles" });

  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const hashedPassword = await bcrypt.hash("SecurePassword123", 10);
      const defaultAdmin = new Admin({
        email: "admin@example.com",
        password: hashedPassword,
        fullName: "System Administrator",
        isSuperAdmin: true,
      });

      await defaultAdmin.save();
      console.log("🔑 Default admin account created:", defaultAdmin.email);
    }
  } catch (err) {
    console.error("Error creating default admin:", err);
  }
});

// ======================
// MODELS
// ======================

const applicantCounterSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  seq: { type: Number, default: 1000 }
}, { collection: "ApplicantCounters" });

const ApplicantCounter = mongoose.model("ApplicantCounter", applicantCounterSchema);

const applicantSchema = new mongoose.Schema({
  applicantId: {
    type: String,
    unique: true,
    uppercase: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8
  },
  status: { 
    type: String, 
    default: "Pending Review",
    enum: [
      "Pending Review", 
      "Under Assessment", 
      "Evaluated - Passed", 
      "Evaluated - Failed", 
      "Rejected",
      "Approved"
    ]
  },
  assignedAssessors: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Assessor' 
  }],
  evaluations: [{
    assessorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Assessor',
      required: true
    },
    educationalQualification: {
      score: { type: Number, min: 0, max: 20 },
      comments: String,
      breakdown: [{
        criteria: String,
        points: Number
      }]
    },
    workExperience: {
      score: { type: Number, min: 0, max: 40 },
      comments: String,
      breakdown: [{
        criteria: String,
        points: Number
      }]
    },
    professionalAchievements: {
      score: { type: Number, min: 0, max: 25 },
      comments: String,
      breakdown: [{
        criteria: String,
        points: Number
      }]
    },
    interview: {
      score: { type: Number, min: 0, max: 15 },
      comments: String,
      breakdown: [{
        criteria: String,
        points: Number
      }]
    },
    totalScore: { type: Number, min: 0, max: 100 },
    isPassed: Boolean,
    status: {
      type: String,
      enum: ['draft', 'finalized'],
      default: 'draft'
    },
    evaluatedAt: { 
      type: Date, 
      default: Date.now 
    },
    finalizedAt: Date,
    finalComments: String
  }],
  evaluationComments: [{
    assessorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Assessor'
    },
    comments: String,
    date: {
      type: Date,
      default: Date.now
    },
    evaluationId: {
      type: mongoose.Schema.Types.ObjectId
    }
  }],
  finalScore: {
    type: Number,
    min: 0,
    max: 100
  },
  isPassed: Boolean,
  personalInfo: {
    firstname: String,
    middlename: String,
    lastname: String,
    suffix: String,
    gender: String,
    age: Number,
    occupation: String,
    nationality: String,
    civilstatus: String,
    birthDate: Date,
    birthplace: String,
    mobileNumber: String,
    telephoneNumber: String,
    emailAddress: String,
    country: String,
    province: String,
    city: String,
    street: String,
    zipCode: String,
    firstPriorityCourse: String,
    secondPriorityCourse: String,
    thirdPriorityCourse: String,
  },
  files: [{
    fileId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    name: String,
    type: String,
    label: {
        type: String,
        default: 'initial-submission'
    },
    uploadDate: {
        type: Date,
        default: Date.now
    }
  }],
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
}, { collection: "Applicants" });

const Applicant = mongoose.model("Applicant", applicantSchema);

const assessorCounterSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  seq: { type: Number, default: 1000 }
}, { collection: "AssessorCounters" });

const AssessorCounter = mongoose.model("AssessorCounter", assessorCounterSchema);

const assessorSchema = new mongoose.Schema({
  email: { 
    type: String, 
    unique: true, 
    required: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8,
  },
  assessorId: { 
    type: String, 
    unique: true,
    uppercase: true
  },
  fullName: {
    type: String,
    required: true
  },
  expertise: {
    type: String,
    required: true,
    enum: ["engineering", "education", "business", "information_technology", 
           "health_sciences", "arts_sciences", "architecture", 
           "industrial_technology", "hospitality_management", "other"]
  },
  assessorType: {
    type: String,
    required: true,
    enum: ["external", "internal"]
  },
  isApproved: { 
    type: Boolean, 
    default: true 
  },
  assignedApplicants: [{
    applicantId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Applicant'
    },
    fullName: String,
    course: String,
    dateAssigned: {
      type: Date,
      default: Date.now
    },
    status: String
  }],
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastLogin: Date
}, { collection: "Assessors" });

const Assessor = mongoose.model("Assessor", assessorSchema);

const adminSchema = new mongoose.Schema({
  email: { 
    type: String, 
    unique: true, 
    required: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8,
  },
  fullName: {
    type: String,
    required: true
  },
  isSuperAdmin: {
    type: Boolean,
    default: false
  },
  lastLogin: Date,
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
}, { collection: "Admins" });

const Admin = mongoose.model("Admin", adminSchema);

const scoringSchema = new mongoose.Schema({
  applicantId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Applicant',
    required: true 
  },
  assessorId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Assessor',
    required: true 
  },
  educationalQualification: {
    score: { type: Number, min: 0, max: 20 },
    comments: String,
    breakdown: [{
      criteria: String,
      points: Number
    }]
  },
  workExperience: {
    score: { type: Number, min: 0, max: 40 },
    comments: String,
    breakdown: [{
      criteria: String,
      points: Number
    }]
  },
  professionalAchievements: {
    score: { type: Number, min: 0, max: 25 },
    comments: String,
    breakdown: [{
      criteria: String,
      points: Number
    }]
  },
  interview: {
    score: { type: Number, min: 0, max: 15 },
    comments: String,
    breakdown: [{
      criteria: String,
      points: Number
    }]
  },
  totalScore: { type: Number, min: 0, max: 100 },
  isPassed: Boolean,
  status: {
    type: String,
    enum: ['draft', 'finalized'],
    default: 'draft'
  },
  evaluatedAt: { 
    type: Date, 
    default: Date.now 
  },
  finalizedAt: Date,
  finalComments: String
}, { collection: "Evaluations" });

const Evaluation = mongoose.model('Evaluation', scoringSchema);

// ======================
// MIDDLEWARE
// ======================

const applicantAuthMiddleware = async (req, res, next) => {
  const token = req.cookies.applicantToken;
  
  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ======================
// UTILITY FUNCTIONS
// ======================

async function getNextApplicantId() {
  const counter = await ApplicantCounter.findByIdAndUpdate(
    'applicantId',
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return `APP${counter.seq.toString().padStart(4, '0')}`;
}

async function getNextAssessorId() {
  const counter = await AssessorCounter.findByIdAndUpdate(
    'assessorId',
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return `AST${counter.seq.toString().padStart(4, '0')}`;
}

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ======================
// ROUTES
// ======================

// Default route
app.get("/", (req, res) => {
  res.send("ETEEAP Server is running");
});

// ======================
// APPLICANT ROUTES
// ======================

// Applicant Registration
app.post("/api/applicants/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: "Email and password are required" 
      });
    }

    // Check if email already exists
    const existingUser = await Applicant.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        error: "Email already registered" 
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
      status: "Pending Review"
    });

    // Save to database
    await newApplicant.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newApplicant._id, 
        role: "applicant",
        email: newApplicant.email
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: "1h" }
    );

    // Set cookie
    res.cookie("applicantToken", token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/"
    });

    // Successful response
    res.status(201).json({ 
      success: true, 
      message: "Registration successful!",
      data: {
        userId: newApplicant._id,
        applicantId: newApplicant.applicantId,
        email: newApplicant.email
      }
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Registration failed",
      details: error.message
    });
  }
});

// Applicant Login
app.post("/api/applicants/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const applicant = await Applicant.findOne({ email: email.toLowerCase() });
    if (!applicant) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
      });
    }

    const isMatch = await bcrypt.compare(password, applicant.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
      });
    }

    const token = jwt.sign(
      { 
        userId: applicant._id, 
        role: "applicant",
        email: applicant.email
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: "1h" }
    );

    res.cookie("applicantToken", token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/"
    });

    res.json({ 
      success: true, 
      message: "Login successful",
      data: {
        userId: applicant._id,
        email: applicant.email,
        applicantId: applicant.applicantId,
        status: applicant.status
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Login failed" 
    });
  }
});

// Get Applicant Profile
app.get("/api/applicants/profile", applicantAuthMiddleware, async (req, res) => {
  try {
    const applicant = await Applicant.findById(req.applicant.userId)
      .select('-password -__v');

    if (!applicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      data: applicant 
    });
  } catch (error) {
    console.error('Error fetching applicant profile:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch applicant profile' 
    });
  }
});

// Update Personal Info
app.post("/api/applicants/update-info", applicantAuthMiddleware, upload.array('files'), async (req, res) => {
  try {
    const { personalInfo } = req.body;
    const userId = req.applicant.userId;

    // Validate input
    if (!personalInfo) {
      return res.status(400).json({
        success: false,
        error: 'Personal info is required'
      });
    }

    // Parse personalInfo if it's a string
    let parsedInfo;
    try {
      parsedInfo = typeof personalInfo === 'string' ? JSON.parse(personalInfo) : personalInfo;
    } catch (parseError) {
      return res.status(400).json({
        success: false,
        error: 'Invalid personal info format'
      });
    }

    // Prepare update data
    const updateData = {
      personalInfo: parsedInfo,
      updatedAt: new Date()
    };

    // Handle file uploads if any
    if (req.files && req.files.length > 0) {
      const files = req.files.map(file => ({
        fileId: new mongoose.Types.ObjectId(),
        name: file.originalname,
        type: file.mimetype,
        label: 'initial-submission',
        uploadDate: new Date()
      }));

      updateData.$push = { files: { $each: files } };
    }

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      userId,
      updateData,
      { new: true }
    ).select('-password');

    res.status(200).json({ 
      success: true,
      message: 'Personal information updated successfully',
      data: updatedApplicant
    });
  } catch (error) {
    console.error("Error updating personal info:", error);
    res.status(500).json({ 
      success: false,
      error: 'Error updating personal info',
      details: error.message
    });
  }
});

// Applicant Auth Status
app.get("/api/applicants/auth-status", async (req, res) => {
  try {
    const token = req.cookies.applicantToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const applicant = await Applicant.findOne({ _id: decoded.userId }).select('-password');
    
    if (!applicant) {
      return res.status(200).json({ 
        authenticated: false,
        message: "Applicant not found"
      });
    }

    res.status(200).json({ 
      authenticated: true,
      user: {
        _id: applicant._id,
        email: applicant.email,
        personalInfo: applicant.personalInfo,
        files: applicant.files,
        status: applicant.status
      }
    });
  } catch (err) {
    console.error("Applicant auth status error:", err);
    res.status(200).json({ 
      authenticated: false,
      message: "Invalid token"
    });
  }
});

// Applicant Logout
app.post("/api/applicants/logout", (req, res) => {
  res.clearCookie("applicantToken");
  res.json({ success: true, message: "Logged out successfully" });
});

// ======================
// ASSESSOR ROUTES
// ======================

// Assessor Registration
app.post("/api/assessors/register", async (req, res) => {
  const { email, password, fullName, expertise, assessorType } = req.body;

  try {
    if (!email || !password || !fullName || !expertise || !assessorType) {
      return res.status(400).json({ 
        success: false, 
        error: "All fields are required" 
      });
    }

    const assessorId = await getNextAssessorId();
    const existing = await Assessor.findOne({ email: email.toLowerCase() });
    
    if (existing) {
      return res.status(400).json({ 
        success: false, 
        error: "Email already registered" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAssessor = new Assessor({ 
      email: email.toLowerCase(),
      password: hashedPassword,
      assessorId,
      fullName,
      expertise,
      assessorType
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
        assessorType: newAssessor.assessorType
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Registration failed - Server error"
    });
  }
});

// Assessor Login
app.post("/api/assessors/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const assessor = await Assessor.findOne({ 
      email: { $regex: new RegExp(`^${email}$`, 'i') }
    });

    if (!assessor) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
      });
    }

    if (!assessor.isApproved) {
      return res.status(403).json({ 
        success: false, 
        error: "Account pending admin approval" 
      });
    }

    const isMatch = await bcrypt.compare(password, assessor.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
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
        assessorType: assessor.assessorType
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: "1h" }
    );

    res.cookie("assessorToken", token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/"
    });

    res.json({ 
      success: true, 
      message: "Login successful",
      data: {
        assessorId: assessor.assessorId,
        email: assessor.email,
        fullName: assessor.fullName,
        expertise: assessor.expertise,
        assessorType: assessor.assessorType
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Login failed" 
    });
  }
});

// Get Assessor Profile
app.get("/api/assessors/profile", assessorAuthMiddleware, async (req, res) => {
  try {
    const assessor = await Assessor.findById(req.assessor.userId)
      .select('-password -__v');

    if (!assessor) {
      return res.status(404).json({ 
        success: false, 
        error: 'Assessor not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      data: assessor 
    });
  } catch (error) {
    console.error('Error fetching assessor profile:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch assessor profile' 
    });
  }
});

// Assessor Auth Status
app.get("/api/assessors/auth-status", async (req, res) => {
  try {
    const token = req.cookies.assessorToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const assessor = await Assessor.findOne({ _id: decoded.userId }).select('-password');
    
    if (!assessor) {
      return res.status(200).json({ 
        authenticated: false,
        message: "Assessor not found"
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
        isApproved: assessor.isApproved
      }
    });
  } catch (err) {
    console.error("Auth status error:", err);
    res.status(200).json({ 
      authenticated: false,
      message: "Invalid token"
    });
  }
});

// Assessor Logout
app.post("/api/assessors/logout", (req, res) => {
  res.clearCookie("assessorToken");
  res.json({ success: true, message: "Logged out successfully" });
});

// Get Assigned Applicants
app.get("/api/assessors/applicants", assessorAuthMiddleware, async (req, res) => {
  try {
    const assessorId = req.assessor.userId;
    
    const applicants = await Applicant.find({ 
      assignedAssessors: assessorId,
      status: "Under Assessment"
    })
    .select('applicantId personalInfo status createdAt finalScore')
    .sort({ createdAt: -1 });

    const formattedApplicants = applicants.map(applicant => {
      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo ? 
          `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''}`.trim() : 
          'No name provided',
        course: applicant.personalInfo?.firstPriorityCourse || 'Not specified',
        applicationDate: applicant.createdAt,
        score: applicant.finalScore,
        status: applicant.status || 'Under Assessment'
      };
    });

    res.status(200).json({ 
      success: true,
      data: formattedApplicants 
    });
  } catch (error) {
    console.error('Error fetching assigned applicants:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch assigned applicants' 
    });
  }
});

// Get Applicant Details
app.get("/api/assessors/applicants/:id", assessorAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.id;
    const assessorId = req.assessor.userId;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId
    })
    .select('-password -__v')
    .populate('assignedAssessors', 'assessorId fullName expertise');

    if (!applicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found or not assigned to you' 
      });
    }

    const formattedApplicant = {
      _id: applicant._id,
      applicantId: applicant.applicantId,
      email: applicant.email,
      status: applicant.status,
      createdAt: applicant.createdAt,
      personalInfo: applicant.personalInfo || {},
      files: applicant.files || [],
      assignedAssessors: applicant.assignedAssessors,
      name: applicant.personalInfo ? 
        `${applicant.personalInfo.firstname || ''} ${applicant.personalInfo.lastname || ''}`.trim() : 
        'No name provided',
      course: applicant.personalInfo?.firstPriorityCourse || 'Not specified'
    };

    res.status(200).json({ 
      success: true,
      data: formattedApplicant 
    });
  } catch (error) {
    console.error('Error fetching applicant:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch applicant' 
    });
  }
});

// Submit Evaluation
app.post("/api/assessors/evaluations", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId, scores } = req.body;
    const assessorId = req.assessor.userId;

    if (!applicantId || !scores) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields"
      });
    }

    // Calculate total score
    const totalScore = 
      (scores.educationalQualification?.score || 0) +
      (scores.workExperience?.score || 0) +
      (scores.professionalAchievements?.score || 0) +
      (scores.interview?.score || 0);

    const isPassed = totalScore >= 60;

    const evaluationData = {
      assessorId: new mongoose.Types.ObjectId(assessorId),
      educationalQualification: {
        score: scores.educationalQualification?.score || 0,
        comments: scores.educationalQualification?.comments || '',
        breakdown: scores.educationalQualification?.breakdown || []
      },
      workExperience: {
        score: scores.workExperience?.score || 0,
        comments: scores.workExperience?.comments || '',
        breakdown: scores.workExperience?.breakdown || []
      },
      professionalAchievements: {
        score: scores.professionalAchievements?.score || 0,
        comments: scores.professionalAchievements?.comments || '',
        breakdown: scores.professionalAchievements?.breakdown || []
      },
      interview: {
        score: scores.interview?.score || 0,
        comments: scores.interview?.comments || '',
        breakdown: scores.interview?.breakdown || []
      },
      totalScore,
      isPassed,
      status: 'draft',
      evaluatedAt: new Date()
    };

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      {
        $push: { evaluations: evaluationData },
        $set: { 
          status: "Under Assessment",
          updatedAt: new Date() 
        }
      },
      { new: true }
    );

    if (!updatedApplicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found"
      });
    }

    res.status(200).json({
      success: true,
      message: "Evaluation saved successfully",
      data: {
        evaluation: evaluationData,
        applicant: updatedApplicant
      }
    });
  } catch (error) {
    console.error('Error saving evaluation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to save evaluation',
      details: error.message
    });
  }
});

// Finalize Evaluation
app.post("/api/assessors/evaluations/finalize", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId, comments } = req.body;
    const assessorId = req.assessor.userId;

    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId
    });

    if (!applicant) {
      return res.status(404).json({
        success: false,
        error: "Applicant not found or not assigned to you"
      });
    }

    const evaluationIndex = applicant.evaluations.length - 1;
    if (evaluationIndex < 0) {
      return res.status(400).json({
        success: false,
        error: "No evaluation found to finalize"
      });
    }

    const evaluation = applicant.evaluations[evaluationIndex];
    const newStatus = evaluation.totalScore >= 60 
      ? "Evaluated - Passed" 
      : "Evaluated - Failed";

    const updatedApplicant = await Applicant.findOneAndUpdate(
      {
        _id: applicantId,
        [`evaluations.${evaluationIndex}.assessorId`]: assessorId
      },
      {
        $set: {
          status: newStatus,
          finalScore: evaluation.totalScore,
          isPassed: evaluation.isPassed,
          [`evaluations.${evaluationIndex}.status`]: 'finalized',
          [`evaluations.${evaluationIndex}.finalComments`]: comments,
          [`evaluations.${evaluationIndex}.finalizedAt`]: new Date()
        },
        $push: {
          evaluationComments: {
            assessorId: assessorId,
            comments: comments,
            date: new Date(),
            evaluationId: applicant.evaluations[evaluationIndex]._id || new mongoose.Types.ObjectId()
          }
        }
      },
      { new: true }
    );

    res.status(200).json({
      success: true,
      message: "Evaluation finalized successfully",
      data: updatedApplicant
    });
  } catch (error) {
    console.error('Error finalizing evaluation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to finalize evaluation'
    });
  }
});

// ======================
// ADMIN ROUTES
// ======================

// Admin Registration
app.post("/api/admins/register", async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password || !fullName) {
      return res.status(400).json({ 
        success: false, 
        error: "All fields are required" 
      });
    }

    const adminCount = await Admin.countDocuments();
    let isSuperAdmin = false;

    if (adminCount > 0) {
      const token = req.cookies.adminToken;
      
           if (!token) {
        return res.status(401).json({ 
          success: false, 
          error: "Authentication required - please login first" 
        });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const requestingAdmin = await Admin.findById(decoded.userId);
        
        if (!requestingAdmin || !requestingAdmin.isSuperAdmin) {
          return res.status(403).json({ 
            success: false, 
            error: "Only super admins can register new admins" 
          });
        }
      } catch (err) {
        return res.status(401).json({ 
          success: false, 
          error: "Invalid authentication token" 
        });
      }
    } else {
      isSuperAdmin = true;
    }

    const existing = await Admin.findOne({ email: email.toLowerCase() });
    
    if (existing) {
      return res.status(400).json({ 
        success: false, 
        error: "Email already registered" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ 
      email: email.toLowerCase(),
      password: hashedPassword,
      fullName,
      isSuperAdmin
    });

    await newAdmin.save();

    return res.status(201).json({ 
      success: true, 
      message: "Admin registration successful",
      data: {
        email: newAdmin.email,
        fullName: newAdmin.fullName,
        isSuperAdmin: newAdmin.isSuperAdmin,
        createdAt: newAdmin.createdAt
      }
    });
  } catch (error) {
    console.error("Admin registration error:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Admin registration failed - Server error"
    });
  }
});

// Admin Login
app.post("/api/admins/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ 
      email: { $regex: new RegExp(`^${email}$`, 'i') }
    });

    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
      });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        error: "Invalid credentials" 
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
        isSuperAdmin: admin.isSuperAdmin
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: "8h" }
    );

    res.cookie("adminToken", token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production",
      maxAge: 28800000,
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/"
    });

    res.json({ 
      success: true, 
      message: "Login successful",
      data: {
        email: admin.email,
        fullName: admin.fullName,
        isSuperAdmin: admin.isSuperAdmin
      }
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Login failed" 
    });
  }
});

// Get Admin Profile
app.get("/api/admins/profile", adminAuthMiddleware, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.userId)
      .select('-password -__v');

    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        error: 'Admin not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      data: admin 
    });
  } catch (error) {
    console.error('Error fetching admin profile:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch admin profile' 
    });
  }
});

// Admin Auth Status
app.get("/api/admins/auth-status", async (req, res) => {
  try {
    const token = req.cookies.adminToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findOne({ _id: decoded.userId }).select('-password');
    
    if (!admin) {
      return res.status(200).json({ 
        authenticated: false,
        message: "Admin not found"
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
        lastLogin: admin.lastLogin
      }
    });
  } catch (err) {
    console.error("Admin auth status error:", err);
    res.status(200).json({ 
      authenticated: false,
      message: "Invalid token"
    });
  }
});

// Admin Logout
app.post("/api/admins/logout", (req, res) => {
  res.clearCookie("adminToken");
  res.json({ success: true, message: "Admin logged out successfully" });
});

// Get All Applicants
app.get("/api/admins/applicants", adminAuthMiddleware, async (req, res) => {
  try {
    const applicants = await Applicant.find({})
      .select('-password -files -__v')
      .sort({ createdAt: -1 });

    const formattedApplicants = applicants.map(applicant => {
      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo ? 
          `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''} ${applicant.personalInfo.middlename || ''}`.trim() : 
          'No name provided',
        course: applicant.personalInfo?.firstPriorityCourse || 'Not specified',
        applicationDate: applicant.createdAt || new Date(),
        currentScore: applicant.finalScore || 0,
        status: applicant.status || 'Pending Review'
      };
    });

    res.status(200).json({ 
      success: true,
      data: formattedApplicants 
    });
  } catch (error) {
    console.error('Error fetching applicants:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch applicants' 
    });
  }
});

// Get Applicant Details
app.get("/api/admins/applicants/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const applicant = await Applicant.findById(applicantId)
      .select('-password -__v')
      .populate('assignedAssessors', 'assessorId fullName expertise')
      .populate('evaluations');

    if (!applicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found' 
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
      name: applicant.personalInfo ? 
        `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''} ${applicant.personalInfo.middlename || ''}`.trim() : 
        'No name provided',
      course: applicant.personalInfo?.firstPriorityCourse || 'Not specified'
    };

    res.status(200).json({ 
      success: true,
      data: formattedApplicant 
    });
  } catch (error) {
    console.error('Error fetching applicant:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch applicant' 
    });
  }
});

// Approve Applicant
app.post("/api/admins/applicants/:id/approve", adminAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      { status: "Approved" },
      { new: true }
    ).select('-password -files -__v');

    if (!updatedApplicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      message: 'Applicant approved successfully',
      data: updatedApplicant
    });
  } catch (error) {
    console.error('Error approving applicant:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to approve applicant' 
    });
  }
});

// Reject Applicant
app.post("/api/admins/applicants/:id/reject", adminAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const updatedApplicant = await Applicant.findByIdAndUpdate(
      applicantId,
      { status: "Rejected" },
      { new: true }
    ).select('-password -files -__v');

    if (!updatedApplicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      message: 'Applicant rejected successfully',
      data: updatedApplicant
    });
  } catch (error) {
    console.error('Error rejecting applicant:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to reject applicant' 
    });
  }
});

// Assign Assessor to Applicant
app.post("/api/admins/applicants/assign-assessor", adminAuthMiddleware, async (req, res) => {
  try {
    const { applicantId, assessorId } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId) || !mongoose.Types.ObjectId.isValid(assessorId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid IDs provided' 
      });
    }

    const [applicant, assessor] = await Promise.all([
      Applicant.findById(applicantId),
      Assessor.findById(assessorId)
    ]);

    if (!applicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found' 
      });
    }

    if (!assessor || !assessor.isApproved) {
      return res.status(400).json({
        success: false,
        error: 'Assessor not found or not approved'
      });
    }

    // Get applicant details for assignment record
    const applicantFullName = applicant.personalInfo ? 
      `${applicant.personalInfo.firstname || ''} ${applicant.personalInfo.lastname || ''}`.trim() : 
      'No name provided';
    const applicantCourse = applicant.personalInfo?.firstPriorityCourse || 'Not specified';

    // Update both documents
    const [updatedApplicant, updatedAssessor] = await Promise.all([
      Applicant.findByIdAndUpdate(
        applicantId,
        { 
          status: "Under Assessment",
          $addToSet: { assignedAssessors: assessorId }
        },
        { new: true }
      ).select('-password -__v'),
      
      Assessor.findByIdAndUpdate(
        assessorId,
        { 
          $addToSet: { 
            assignedApplicants: {
              applicantId: applicant._id,
              fullName: applicantFullName,
              course: applicantCourse,
              status: "Under Assessment"
            }
          } 
        },
        { new: true }
      ).select('-password -__v')
    ]);

    res.status(200).json({ 
      success: true,
      message: 'Assessor assigned successfully',
      data: {
        applicant: updatedApplicant,
        assessor: {
          _id: assessor._id,
          assessorId: assessor.assessorId,
          fullName: assessor.fullName,
          assignedApplicants: updatedAssessor.assignedApplicants
        }
      }
    });
  } catch (error) {
    console.error('Error assigning assessor:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to assign assessor',
      details: error.message
    });
  }
});

// Get Available Assessors
app.get("/api/admins/available-assessors", adminAuthMiddleware, async (req, res) => {
  try {
    const assessors = await Assessor.find({ isApproved: true })
      .select('_id assessorId fullName expertise assessorType')
      .sort({ fullName: 1 });

    res.status(200).json({
      success: true,
      data: assessors
    });
  } catch (error) {
    console.error('Error fetching assessors:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch assessors'
    });
  }
});

// Get Dashboard Stats
app.get("/api/admins/dashboard-stats", adminAuthMiddleware, async (req, res) => {
  try {
    const totalApplicants = await Applicant.countDocuments();
    const newApplicants = await Applicant.countDocuments({ 
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    const pendingReview = await Applicant.countDocuments({ status: "Pending Review" });
    const underAssessment = await Applicant.countDocuments({ status: "Under Assessment" });
    const evaluatedPassed = await Applicant.countDocuments({ status: "Evaluated - Passed" });
    const evaluatedFailed = await Applicant.countDocuments({ status: "Evaluated - Failed" });
    const rejected = await Applicant.countDocuments({ status: "Rejected" });
    const approved = await Applicant.countDocuments({ status: "Approved" });

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
        approved
      }
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch dashboard stats'
    });
  }
});

// Get All Assessors
app.get("/api/admins/assessors", adminAuthMiddleware, async (req, res) => {
  try {
    const assessors = await Assessor.find({})
      .populate('assignedApplicants')
      .select('-password -__v')
      .sort({ createdAt: -1 });

    const formattedAssessors = assessors.map(assessor => ({
      ...assessor.toObject(),
      applicantsCount: assessor.assignedApplicants.length,
      assignedApplicants: assessor.assignedApplicants.map(applicant => ({
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo ? 
          `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''}`.trim() : 
          'No name provided',
        status: applicant.status || 'Under Assessment'
      }))
    }));

    res.status(200).json({
      success: true,
      data: formattedAssessors
    });
  } catch (error) {
    console.error('Error fetching assessors:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch assessors'
    });
  }
});

// Get Assessor Details
app.get("/api/admins/assessors/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const assessor = await Assessor.findById(req.params.id)
      .select('-password -__v')
      .populate({
        path: 'assignedApplicants.applicantId',
        select: 'applicantId personalInfo status files evaluations',
        model: 'Applicant'
      });

    if (!assessor) {
      return res.status(404).json({
        success: false,
        error: 'Assessor not found'
      });
    }

    // Format the response with complete applicant data
    const formattedAssessor = {
      ...assessor.toObject(),
      assignedApplicants: assessor.assignedApplicants.map(assignment => {
        const applicant = assignment.applicantId || {};
        return {
          _id: applicant._id || assignment.applicantId,
          applicantId: applicant.applicantId || 'N/A',
          fullName: applicant.personalInfo ? 
            `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''}`.trim() : 
            assignment.fullName || 'No name provided',
          course: applicant.personalInfo?.firstPriorityCourse || assignment.course || 'Not specified',
          dateAssigned: assignment.dateAssigned,
          status: applicant.status || assignment.status || 'Under Assessment'
        };
      })
    };

    res.status(200).json({
      success: true,
      data: formattedAssessor
    });
  } catch (error) {
    console.error('Error fetching assessor:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch assessor',
      details: error.message
    });
  }
});

// Update Assessor
app.put("/api/admins/assessors/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const { fullName, email, assessorType, expertise, isApproved } = req.body;
    
    const updatedAssessor = await Assessor.findByIdAndUpdate(
      req.params.id,
      { fullName, email, assessorType, expertise, isApproved },
      { new: true, runValidators: true }
    ).select('-password -__v');

    if (!updatedAssessor) {
      return res.status(404).json({
        success: false,
        error: 'Assessor not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Assessor updated successfully',
      data: updatedAssessor
    });
  } catch (error) {
    console.error('Error updating assessor:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update assessor'
    });
  }
});

// Delete Assessor
app.delete("/api/admins/assessors/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const deletedAssessor = await Assessor.findByIdAndDelete(req.params.id);

    if (!deletedAssessor) {
      return res.status(404).json({
        success: false,
        error: 'Assessor not found'
      });
    }

    // Remove this assessor from any assigned applicants
    await Applicant.updateMany(
      { assignedAssessors: deletedAssessor._id },
      { $pull: { assignedAssessors: deletedAssessor._id } }
    );

    res.status(200).json({
      success: true,
      message: 'Assessor deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting assessor:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete assessor'
    });
  }
});

// Get All Evaluations
app.get("/api/admins/evaluations", adminAuthMiddleware, async (req, res) => {
  try {
    const evaluations = await Evaluation.find({})
      .populate('applicantId', 'personalInfo status')
      .populate('assessorId', 'assessorId fullName expertise')
      .sort({ finalizedAt: -1 });

    const formattedEvaluations = evaluations.map(eval => {
      const applicant = eval.applicantId;
      const assessor = eval.assessorId;
      
      return {
        _id: eval._id,
        applicantId: applicant._id,
        applicantName: applicant.personalInfo ? 
          `${applicant.personalInfo.lastname}, ${applicant.personalInfo.firstname}` : 
          'No name provided',
        applicantCourse: applicant.personalInfo?.firstPriorityCourse || 'Not specified',
        assessorId: assessor._id,
        assessorName: assessor.fullName,
        assessorExpertise: assessor.expertise,
        totalScore: eval.totalScore,
        isPassed: eval.isPassed,
        status: eval.status,
        evaluatedAt: eval.evaluatedAt,
        finalizedAt: eval.finalizedAt
      };
    });

    res.status(200).json({
      success: true,
      data: formattedEvaluations
    });
  } catch (error) {
    console.error('Error fetching evaluations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch evaluations'
    });
  }
});

// Get Evaluation Details
app.get("/api/admins/evaluations/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const evaluation = await Evaluation.findById(req.params.id)
      .populate('applicantId', 'personalInfo files status')
      .populate('assessorId', 'assessorId fullName expertise assessorType');

    if (!evaluation) {
      return res.status(404).json({
        success: false,
        error: 'Evaluation not found'
      });
    }

    res.status(200).json({
      success: true,
      data: evaluation
    });
  } catch (error) {
    console.error('Error fetching evaluation:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch evaluation'
    });
  }
});

// ======================
// FILE HANDLING ROUTES
// ======================

// Serve Files
app.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;
  
  if (!filename.endsWith('.pdf') || !/^[a-zA-Z0-9_\-\.]+\.pdf$/.test(filename)) {
      return res.status(400).json({ error: 'Only PDF files are supported' });
  }

  const filePath = path.join(__dirname, 'public', 'documents', filename);
  
  if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
  }

  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(filePath);
});

// Upload Files (GridFS)
app.post('/api/files/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded' 
      });
    }

    const readStream = fs.createReadStream(req.file.path);
    const uploadStream = gfs.openUploadStream(req.file.originalname, {
      contentType: req.file.mimetype,
      metadata: {
        uploadDate: new Date(),
        originalName: req.file.originalname,
        size: req.file.size,
        owner: req.body.userId || 'unknown'
      }
    });

    readStream.pipe(uploadStream);

    uploadStream.on('error', (error) => {
      fs.unlinkSync(req.file.path);
      throw error;
    });

    uploadStream.on('finish', () => {
      fs.unlinkSync(req.file.path);
      res.status(201).json({
        success: true,
        message: 'File uploaded successfully',
        fileId: uploadStream.id,
        filename: req.file.originalname,
        size: req.file.size,
        contentType: req.file.mimetype
      });
    });
  } catch (error) {
    console.error('File upload error:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ 
      success: false,
      error: 'File upload failed',
      details: error.message
    });
  }
});

// Download Files
app.get('/api/files/download/:id', async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);
    const file = await conn.db.collection('applicantFiles.files').findOne({ _id: fileId });

    if (!file) {
      return res.status(404).json({ 
        success: false,
        error: 'File not found' 
      });
    }

    res.set('Content-Type', file.contentType);
    res.set('Content-Disposition', `attachment; filename="${file.filename}"`);

    const downloadStream = gfs.openDownloadStream(fileId);
    downloadStream.pipe(res);
  } catch (error) {
    console.error('Error serving file:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to serve file' 
    });
  }
});

// Delete Files
app.delete('/api/files/:id', async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);
    await gfs.delete(fileId);
    res.json({ 
      success: true, 
      message: 'File deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete file' 
    });
  }
});

// ======================
// ERROR HANDLER
// ======================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ======================
// START SERVER
// ======================

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📁 MongoDB collections connected:`);
  console.log(`- Applicants`);
  console.log(`- Assessors`);
  console.log(`- Admins`);
  console.log(`- Evaluations`);
  console.log(`- applicantFiles (GridFS)`);
});
