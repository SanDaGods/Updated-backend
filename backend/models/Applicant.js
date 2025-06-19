const mongoose = require("mongoose");

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

module.exports = mongoose.model("Applicant", applicantSchema);