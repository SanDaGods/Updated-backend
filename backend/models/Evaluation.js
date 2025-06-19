const mongoose = require("mongoose");


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

module.exports= mongoose.model('Evaluation', scoringSchema);