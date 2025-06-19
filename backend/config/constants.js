require("dotenv").config();

module.exports = {
  JWT_SECRET:
    process.env.JWT_SECRET ||
    "3T33@APPR0@GR!M",
  PORT: process.env.PORT || 3000,
};
