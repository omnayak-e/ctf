const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(express.json());
app.use(express.static(__dirname));
app.set("trust proxy", 1);

// 🔐 Allowed Admin Emails
const allowedEmails = [
  "omseshdevnayak@gmail.com",
  "umeshkoli.400078@gmail.com",
  "admin3@gmail.com",
  "admin4@gmail.com"
];

// 🔐 Rate Limiter (OTP abuse protection)
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { message: "Too many OTP requests. Try again later." }
});

app.use("/send-otp", otpLimiter);

// 🔐 Gmail SMTP (Using Environment Variables)
const transport = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Temporary in-memory storage
let otpStore = {};
let authenticatedUsers = {};

// 🔑 Generate 10-character OTP
function generateOTP(length = 10) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  let otp = "";
  for (let i = 0; i < length; i++) {
    otp += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return otp;
}

// 📩 SEND OTP
app.post("/send-otp", async (req, res) => {
  let email = req.body.email;

  if (!email) {
    return res.status(400).json({ message: "Email required" });
  }

  email = email.toLowerCase();

  if (!allowedEmails.includes(email)) {
    return res.status(403).json({ message: "Access denied ❌ Not authorized" });
  }

  const otp = generateOTP(10);

  otpStore[email] = {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0
  };

  try {
    await transport.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Secure Login Code",
      text: `Your secure verification code is:\n\n${otp}\n\nThis code expires in 5 minutes.`
    });

    res.json({ message: "OTP Sent ✅ Check your email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error sending OTP ❌" });
  }
});

// ✅ VERIFY OTP
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

    authenticatedUsers[email] = {
      loginTime: Date.now()
    };

    return res.json({ message: "OTP Verified ✅" });
  } else {
    otpStore[email].attempts++;
    return res.status(401).json({ message: "Invalid OTP ❌" });
  }
});

// 🔐 Dashboard Protection
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

// 🚀 Dynamic PORT for Railway
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});