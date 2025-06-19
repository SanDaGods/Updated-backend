const AssessorCounter = require("../models/AssessorCounter");
const ApplicantCounter = require("../models/ApplicantCounter");

async function getNextAssessorId() {
  const counter = await AssessorCounter.findByIdAndUpdate(
    'assessorId',
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return `AST${counter.seq.toString().padStart(4, '0')}`;
}

async function getNextApplicantId() {
  const counter = await ApplicantCounter.findByIdAndUpdate(
    'applicantId',
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return `AST${counter.seq.toString().padStart(4, '0')}`;
}




module.exports = {
    getNextAssessorId,
    getNextApplicantId,
    
};