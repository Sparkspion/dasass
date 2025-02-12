import express from "express";
import {
  login,
  logout,
  refreshToken,
  register,
  resetPassword,
  sendMfaOtp,
  sendPasswordResetEmail,
  sendVerificationEmail,
  verifyEmail,
  verifyMfaOtp,
} from "../controllers/authController";
import { authenticateUser, authorizeRole } from "../middlewares/authMiddleware";
import { generalLimiter, loginLimiter } from "../middlewares/rateLimit";

const router = express.Router();

router.post("/register", register);
router.post("/login", loginLimiter, login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);

router.get("/admin", authenticateUser, authorizeRole(["admin"]), (req, res) => {
  res.json({ message: "Welcome admin" });
});

router.post("/mfa/send-otp", sendMfaOtp);
router.post("/mfa/verify-otp", verifyMfaOtp);

router.post("/verify-email/send", sendVerificationEmail);
router.get("/verify-email", verifyEmail);

router.post("/password-reset/send", sendPasswordResetEmail);
router.post("/password-reset", resetPassword);

router.use(generalLimiter); // Apply general rate limit to all routes
export default router;
