const express = require("express");
const path = require("path");
const rateLimit = require("express-rate-limit");
const axios = require("axios");

const app = express();

app.use(express.json());
app.use(express.static(__dirname));
app.set("trust proxy", 1);

const allowedEmails = [
  "omseshdevnayak@gmail.com",
  "umeshkoli.400078@gmail.com",
  "admin3@gmail.com",
  "admin4@gmail.com"
];

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { message: "Too many OTP requests. Try again later." }
});

app.use("/send-otp", otpLimiter);

let otpStore = {};
let authenticatedUsers = {};

function generateOTP(length = 10) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  let otp = "";
  for (let i = 0; i < length; i++) {
    otp += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return otp;
}

// 📩 SEND OTP (Mailtrap API)
app.post("/send-otp", async (req, res) => {
  let { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email required" });
  }

  email = email.toLowerCase();

  if (!allowedEmails.includes(email)) {
    return res.status(403).json({ message: "Access denied ❌" });
  }

  const otp = generateOTP(10);

  otpStore[email] = {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0
  };

  try {
    await axios.post(
      "https://send.api.mailtrap.io/api/send",
      {
        from: {
          email: "admin@demo.mailtrap.io",
          name: "CTF Admin"
        },
        to: [{ email }],
        subject: "Your Secure Login Code",
        text: `Your secure verification code is:\n\n${otp}\n\nExpires in 5 minutes.`
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.MAILTRAP_API_TOKEN}`
        }
      }
    );

    res.json({ message: "OTP Sent ✅ Check your email" });

  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ message: "Error sending OTP ❌" });
  }
});

// VERIFY OTP
app.post("/verify-otp", (req, res) => {
  let { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: "Missing data" });
  }

  email = email.toLowerCase();

  if (!otpStore[email]) {
    return res.status(400).json({ message: "No OTP found" });
  }

  if (Date.now() > otpStore[email].expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: "OTP expired ❌" });
  }

  if (otpStore[email].attempts >= 3) {
    delete otpStore[email];
    return res.status(403).json({ message: "Too many failed attempts ❌" });
  }

  if (otpStore[email].otp === otp) {
    delete otpStore[email];
    authenticatedUsers[email] = { loginTime: Date.now() };
    return res.json({ message: "OTP Verified ✅" });
  } else {
    otpStore[email].attempts++;
    return res.status(401).json({ message: "Invalid OTP ❌" });
  }
});

app.get("/dashboard", (req, res) => {
  const email = req.query.email?.toLowerCase();

  if (
    authenticatedUsers[email] &&
    Date.now() - authenticatedUsers[email].loginTime < 10 * 60 * 1000
  ) {
    return res.sendFile(path.join(__dirname, "dashboard.html"));
  }

  res.status(403).send("Unauthorized ❌");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
