require("dotenv").config();

module.exports = {
  JWT_SECRET:
    process.env.JWT_SECRET ||
    "21b4f89a96ecde2d4d88285d15da09017466707bfd345b7d02bd587fb6981e6a",
  PORT: process.env.PORT || 3000,
};
