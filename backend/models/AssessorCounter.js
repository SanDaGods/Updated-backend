const mongoose = require("mongoose");

const assessorCounterSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  seq: { type: Number, default: 1000 }
}, { collection: "AssessorCounters" });

module.exports = mongoose.model("AssessorCounter", assessorCounterSchema);