require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require('body-parser');
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const multer = require('multer');
const fs = require("fs");
const { GridFSBucket, ObjectId } = require('mongodb');
const conn = mongoose.connection;

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "3T33@APPR0@GR!M";

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({ 
  origin: "http://localhost", // or your frontend URL
  credentials: true,
  exposedHeaders: ['set-cookie']
}));
app.use(bodyParser.json());

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// MongoDB Connection
mongoose.connect("mongodb://127.0.0.1:27017/Eteeap", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", async () => {
  console.log("✅ MongoDB connected successfully");
  
  try {
    // Check if any admin exists
    const Admin = mongoose.model('Admin', adminSchema);
    const adminCount = await Admin.countDocuments();
    
    if (adminCount === 0) {
      // Create a default admin if none exists
      const defaultAdmin = new Admin({
        email: 'admin@example.com',
        password: 'SecurePassword123', // In production, you should hash this!
        fullName: 'System Administrator',
        isSuperAdmin: true
      });
      
      await defaultAdmin.save();
      console.log('🔑 Default admin account created:', defaultAdmin.email);
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
});

// Initialize GridFS bucket
let gfs;
conn.once('open', () => {
  gfs = new GridFSBucket(conn.db, {
    bucketName: 'backupFiles'
  });
});

// ======================
// SCHEMAS
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

// ======================
// UTILITY FUNCTIONS
// ======================

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
  res.sendFile(path.join(__dirname, "index.html"));
});

// ======================
// APPLICANT ROUTES
// ======================

async function getNextApplicantId() {
  try {
    const counter = await ApplicantCounter.findByIdAndUpdate(
      'applicantId',
      { $inc: { seq: 1 } },
      { new: true, upsert: true }
    );
    return `APP${counter.seq.toString().padStart(4, '0')}`;
  } catch (error) {
    console.error("Error generating applicant ID:", error);
    // Fallback to timestamp-based ID if counter fails
    return `APP${Date.now().toString().slice(-4)}`;
  }
}

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log("Registration attempt for:", email);

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: "Email and password are required",
        details: "One or more required fields were empty"
      });
    }

    // Check email format with more permissive regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      console.log("Invalid email format:", email);
      return res.status(400).json({
        success: false,
        error: "Invalid email format",
        details: `Please enter a valid email address (e.g., user@example.com). Provided: ${email}`
      });
    }

    // Check password length
    if (password.length < 8) {
      console.log("Password too short");
      return res.status(400).json({
        success: false,
        error: "Password too short",
        details: "Password must be at least 8 characters"
      });
    }

    // Check if email already exists
    const existingUser = await Applicant.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      console.log("Email already exists:", email);
      return res.status(400).json({ 
        success: false, 
        error: "Email already registered",
        details: "This email is already in use"
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
      applicantId
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
        applicantId: newApplicant.applicantId
      }
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Registration failed",
      details: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
});


app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const applicant = await Applicant.findOne({ email });
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
      JWT_SECRET, 
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
        email: applicant.email
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

// Route to serve files
app.get('/file/:id', async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);
    const file = await conn.db.collection('applicantFiles.files').findOne({ _id: fileId });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.set('Content-Type', file.contentType);
    res.set('Content-Disposition', `inline; filename="${file.filename}"`);

    const downloadStream = gfs.openDownloadStream(fileId);
    downloadStream.pipe(res);
  } catch (error) {
    console.error('Error serving file:', error);
    res.status(500).json({ error: 'Failed to serve file' });
  }
});

// Route to delete files
app.delete('/file/:id', async (req, res) => {
  try {
    const fileId = new ObjectId(req.params.id);
    await gfs.delete(fileId);
    res.json({ success: true, message: 'File deleted successfully' });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Add this route before the server starts listening
app.post('/api/submit-documents', upload.array('files'), async (req, res) => {
    try {

        const userId = req.body.userId;

                if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid userId format' 
            });
        }

        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ 
                success: false,
                error: 'No files uploaded' 
            });
        }

        // Process each file
        const uploadResults = await Promise.all(req.files.map(async (file) => {
            return new Promise((resolve, reject) => {
                const readStream = fs.createReadStream(file.path);
                const uploadStream = gfs.openUploadStream(file.originalname, {
                    contentType: file.mimetype,
                    metadata: {
                        uploadDate: new Date(),
                        originalName: file.originalname,
                        size: file.size,
                        label: 'initial-submission',
                        owner: userId
                    }
                });

                uploadStream.on('error', (error) => {
                    fs.unlinkSync(file.path);
                    reject(error);
                });

                uploadStream.on('finish', () => {
                    fs.unlinkSync(file.path);
                    resolve({
                        fileId: uploadStream.id,
                        filename: file.originalname,
                        size: file.size,
                        contentType: file.mimetype
                    });
                });

                readStream.pipe(uploadStream);
            });
        }));

        res.json({
            success: true,
            message: `${uploadResults.length} files uploaded successfully`,
            files: uploadResults
        });

    } catch (error) {
        console.error('File upload error:', error);
        
        // Clean up any remaining temp files
        if (req.files) {
            req.files.forEach(file => {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            });
        }

        res.status(500).json({ 
            success: false,
            error: 'File upload failed',
            details: error.message
        });
    }
});

app.post("/api/update-personal-info", upload.array('files'), async (req, res) => {
    try {
        // Get the userId from the request body or form data
        const userId = req.body.userId;
        let personalInfo = req.body.personalInfo;
        
        // If personalInfo is a string, parse it
        if (typeof personalInfo === 'string') {
            try {
                personalInfo = JSON.parse(personalInfo);
            } catch (parseError) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid personalInfo format',
                    details: parseError.message
                });
            }
        }

        // Validate userId
        if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid userId format' 
            });
        }

        // Basic validation of required fields
        const requiredFields = [
            'firstname', 'lastname', 'gender', 'age', 'occupation', 
            'nationality', 'civilstatus', 'birthDate', 'birthplace',
            'mobileNumber', 'emailAddress', 'country', 'province',
            'city', 'street', 'zipCode', 'firstPriorityCourse'
        ];
        
        const missingFields = requiredFields.filter(field => !personalInfo[field]);
        if (missingFields.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields',
                missingFields
            });
        }

        // Handle file uploads if any
        const files = [];
        if (req.files && req.files.length > 0) {
            for (const file of req.files) {
                const metadata = {
                    type: file.mimetype,
                    size: file.size,
                    originalName: file.originalname,
                    uploadDate: new Date(),
                    label: 'initial-submission'
                };

                // Upload to GridFS
                const uploadStream = gfs.openUploadStream(file.originalname, {
                    contentType: file.mimetype,
                    metadata: metadata
                });

                // Create read stream from the uploaded file
                const readStream = fs.createReadStream(file.path);
                
                // Pipe the file data to GridFS
                await new Promise((resolve, reject) => {
                    readStream.pipe(uploadStream)
                        .on('error', reject)
                        .on('finish', resolve);
                });

                // Add file reference
                files.push({
                    fileId: uploadStream.id,
                    name: file.originalname,
                    type: file.mimetype,
                    label: 'initial-submission',
                    uploadDate: new Date()
                });

                // Delete the temporary file
                fs.unlinkSync(file.path);
            }
        }

        // Prepare update data
        const updateData = {
            personalInfo: personalInfo,
            updatedAt: new Date()
        };

        // Add file references if any
        if (files.length > 0) {
            updateData.$push = {
                files: {
                    $each: files
                }
            };
        }

        const updatedApplicant = await Applicant.findByIdAndUpdate(
            userId,
            updateData,
            { new: true }
        ).select('-password');

        if (!updatedApplicant) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found' 
            });
        }

        res.status(200).json({ 
            success: true,
            message: 'Personal information and documents updated successfully',
            data: updatedApplicant
        });
    } catch (error) {
        console.error("Error updating personal info:", error);
        
        // Clean up any uploaded files if error occurred
        if (req.files) {
            req.files.forEach(file => {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            });
        }

        res.status(500).json({ 
            success: false,
            error: 'Error updating personal info',
            details: error.message
        });
    }
});


app.get("/api/profile/:id", applicantAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.id;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const applicant = await Applicant.findById(applicantId)
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


app.get("/applicant/auth-status", async (req, res) => {
  try {
    const token = req.cookies.applicantToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
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

app.post("/applicant/logout", (req, res) => {
  res.clearCookie("applicantToken");
  res.json({ success: true, message: "Logged out successfully" });
});

// ======================
// ASSESSOR ROUTES
// ======================

app.post("/assessor/register", async (req, res) => {
  const { email, password, fullName, expertise, assessorType } = req.body;

  try {
    if (!email || !password || !fullName || !expertise || !assessorType) {
      return res.status(400).json({ 
        success: false, 
        error: "All fields are required" 
      });
    }

    if (password.length < 8 || password.length > 16) {
      return res.status(400).json({
        success: false,
        error: "Password must be 8-16 characters"
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

app.post("/assessor/login", async (req, res) => {
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
      JWT_SECRET, 
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

app.get("/assessor-dashboard", assessorAuthMiddleware, (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "frontend", "AssessorSide", "AssessorDashboard", "AssessorDashboard.html")
  );
});

app.get("/assessor/auth-status", async (req, res) => {
  try {
    const token = req.cookies.assessorToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
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
        isApproved: assessor.isApproved,
        createdAt: assessor.createdAt,
        lastLogin: assessor.lastLogin
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

app.post("/assessor/logout", (req, res) => {
  res.clearCookie("assessorToken");
  res.json({ success: true, message: "Logged out successfully" });
});

app.get("/api/assessor/applicants", assessorAuthMiddleware, async (req, res) => {
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

app.get("/api/assessor/applicants/:id", assessorAuthMiddleware, async (req, res) => {
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

app.get("/api/assessor/applicant-documents/:applicantId", assessorAuthMiddleware, async (req, res) => {
  try {
    const applicantId = req.params.applicantId;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const assessorId = req.assessor.userId;
    const applicant = await Applicant.findOne({
      _id: applicantId,
      assignedAssessors: assessorId
    }).select('files personalInfo');

    if (!applicant) {
      return res.status(404).json({ 
        success: false, 
        error: 'Applicant not found or not assigned to you' 
      });
    }

    const documents = applicant.files.map(file => ({
      name: file.name || path.basename(file.path),
      path: file.path,
      type: file.type || path.extname(file.path).substring(1).toLowerCase(),
      status: 'pending',
      uploadDate: file.uploadDate || new Date()
    }));

    res.status(200).json({ 
      success: true,
      data: {
        applicant: {
          name: applicant.personalInfo ? 
            `${applicant.personalInfo.firstname || ''} ${applicant.personalInfo.lastname || ''}`.trim() : 
            'No name provided',
          course: applicant.personalInfo?.firstPriorityCourse || 'Not specified'
        },
        documents
      }
    });
  } catch (error) {
    console.error('Error fetching applicant documents:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch applicant documents' 
    });
  }
});

app.get("/api/evaluations", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId } = req.query;
    const assessorId = req.assessor.userId;
    
    if (!mongoose.Types.ObjectId.isValid(applicantId)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid applicant ID' 
      });
    }

    const evaluation = await Evaluation.findOne({
      applicantId,
      assessorId
    });

    if (!evaluation) {
      return res.status(200).json({ 
        success: true,
        data: null
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

// In server.js, modify the evaluations POST route:
app.post("/api/evaluations", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId, scores } = req.body;
    const assessorId = req.assessor.userId;

    // Validate input
    if (!applicantId || !scores) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields"
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

    // Update the applicant document
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

app.post("/api/evaluations/finalize", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId, comments } = req.body;
    const assessorId = req.assessor.userId;

    // Find the applicant and their most recent evaluation
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

    // Get the most recent evaluation (last in the array)
    const evaluationIndex = applicant.evaluations.length - 1;
    if (evaluationIndex < 0) {
      return res.status(400).json({
        success: false,
        error: "No evaluation found to finalize"
      });
    }

    const evaluation = applicant.evaluations[evaluationIndex];
    
    // Calculate final status
    const newStatus = evaluation.totalScore >= 60 
      ? "Evaluated - Passed" 
      : "Evaluated - Failed";

    // Update the evaluation in the applicant's evaluations array
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

app.post("/admin/register", async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password || !fullName) {
      return res.status(400).json({ 
        success: false, 
        error: "All fields are required" 
      });
    }

    if (password.length < 8 || password.length > 16) {
      return res.status(400).json({
        success: false,
        error: "Password must be 8-16 characters"
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
        const decoded = jwt.verify(token, JWT_SECRET);
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
      message: "Admin registration successful. Please login.",
      redirectTo: "/frontend/AdminSide/1.adminLogin/adminlogin.html",
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

app.post("/admin/login", async (req, res) => {
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
      JWT_SECRET, 
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
      redirectTo: "/frontend/AdminSide/2.adminDash/admin.html",
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

app.get("/admin/auth-status", async (req, res) => {
  try {
    const token = req.cookies.adminToken;
    
    if (!token) {
      return res.status(200).json({ 
        authenticated: false,
        message: "No token found"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
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

app.post("/admin/logout", (req, res) => {
  res.clearCookie("adminToken");
  res.json({ success: true, message: "Admin logged out successfully" });
});

app.get("/frontend/AdminSide/2.adminDash/admin.html", adminAuthMiddleware, (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "frontend", "AdminSide", "2.adminDash", "admin.html")
  );
});

// In server.js, update the /api/admin/applicants route:
app.get("/api/admin/applicants", adminAuthMiddleware, async (req, res) => {
  try {
    // Remove the limit parameter to always return all applicants
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

app.get("/api/admin/applicants/:id", adminAuthMiddleware, async (req, res) => {
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

app.post("/api/admin/applicants/:id/approve", adminAuthMiddleware, async (req, res) => {
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

app.post("/api/admin/applicants/:id/reject", adminAuthMiddleware, async (req, res) => {
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

app.post("/api/admin/applicants/:id/assign-assessor", adminAuthMiddleware, async (req, res) => {
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

    // Get applicant details for the assignment record
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

app.get("/api/admin/available-assessors", adminAuthMiddleware, async (req, res) => {
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

app.get("/api/admin/dashboard-stats", adminAuthMiddleware, async (req, res) => {
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

    res.status(200).json({
      success: true,
      data: {
        totalApplicants,
        newApplicants,
        pendingReview,
        underAssessment,
        evaluatedPassed,
        evaluatedFailed,
        rejected
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

app.get("/assessor/all", adminAuthMiddleware, async (req, res) => {
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

app.get("/assessor/:id", adminAuthMiddleware, async (req, res) => {
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

app.put("/assessor/:id", adminAuthMiddleware, async (req, res) => {
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

app.delete("/assessor/:id", adminAuthMiddleware, async (req, res) => {
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

app.get("/api/assessor/:id/applicants", adminAuthMiddleware, async (req, res) => {
  try {
    const assessor = await Assessor.findById(req.params.id)
      .populate('assignedApplicants', 'applicantId personalInfo status files evaluations')
      .select('assignedApplicants');

    if (!assessor) {
      return res.status(404).json({
        success: false,
        error: 'Assessor not found'
      });
    }

    const formattedApplicants = assessor.assignedApplicants.map(applicant => {
      const latestEvaluation = applicant.evaluations && applicant.evaluations.length > 0 
        ? applicant.evaluations[applicant.evaluations.length - 1]
        : null;

      return {
        _id: applicant._id,
        applicantId: applicant.applicantId,
        name: applicant.personalInfo ? 
          `${applicant.personalInfo.lastname || ''}, ${applicant.personalInfo.firstname || ''}`.trim() : 
          'No name provided',
        course: applicant.personalInfo?.firstPriorityCourse || 'Not specified',
        status: applicant.status || 'Under Assessment',
        documentsCount: applicant.files ? applicant.files.length : 0,
        latestScore: latestEvaluation ? latestEvaluation.totalScore : null,
        isPassed: latestEvaluation ? latestEvaluation.isPassed : null
      };
    });

    res.status(200).json({
      success: true,
      data: formattedApplicants
    });
  } catch (error) {
    console.error('Error fetching assessor applicants:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch assessor applicants'
    });
  }
});

app.get("/api/admin/evaluations", adminAuthMiddleware, async (req, res) => {
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

app.get("/api/admin/evaluations/:id", adminAuthMiddleware, async (req, res) => {
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

// Serve documents
app.get('/documents/:filename', (req, res) => {
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


// Add this route to server.js
app.get("/api/evaluations/applicant/:applicantId", assessorAuthMiddleware, async (req, res) => {
  try {
    const { applicantId } = req.params;
    const assessorId = req.assessor.userId;

    const evaluations = await Evaluation.find({
      applicantId,
      assessorId
    }).sort({ finalizedAt: -1 });

    res.status(200).json({
      success: true,
      data: evaluations.length > 0 ? evaluations[0] : null
    });
  } catch (error) {
    console.error('Error fetching applicant evaluations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch evaluations'
    });
  }
});


// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});


// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📁 MongoDB collections is connected:`);
  console.log(`- Eteeap.Applicants`);
  console.log(`- Eteeap.Assessors`);
  console.log(`- Eteeap.AssessorCounters`);
  console.log(`- Eteeap.ApplicantCounters`);
  console.log(`- Eteeap.Admins`);
  console.log(`- Eteeap.Evaluations`);
});
