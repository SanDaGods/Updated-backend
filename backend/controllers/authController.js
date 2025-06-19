exports.register = async (req, res) => {
  try {
    console.log("REQ BODY (register):", req.body);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    return res.status(201).json({
      message: "Registration successful",
      data: {
        userId: "mockUserId123",
        applicantId: "mockApplicantId456",
        email,
      },
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ success: false, error: "Internal error", message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    console.log("REQ BODY (login):", req.body);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    // Simulate a successful login (replace with real user lookup and password check)
    return res.status(200).json({
      message: "Login successful",
      data: {
        userId: "mockUserId123",
        email,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, error: "Internal error", message: err.message });
  }
};
