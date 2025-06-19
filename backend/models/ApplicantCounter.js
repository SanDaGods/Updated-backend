const mongoose = require("mongoose");

const applicantCounterSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  seq: { type: Number, default: 1000 }
}, { collection: "ApplicantCounters" });

module.exports = mongoose.model("ApplicantCounter", applicantCounterSchema);