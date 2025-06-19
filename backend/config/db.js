const mongoose = require("mongoose");
const conn = mongoose.connection;
const { GridFSBucket, ObjectId } = require("mongodb");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const connectDB = async () => {
  try {
    await mongoose.connect(
      "mongodb+srv://rtuiflde:rtu_ifldeDB01@cluster0.7ozrymz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("MongoDB connected sucessfully");
  } catch (err) {
    console.error("MongoDB connection error!", err);
    process.exit(1);
  }
};

module.exports = connectDB;
