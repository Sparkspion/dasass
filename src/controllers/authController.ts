import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User";
import speakeasy from "speakeasy";
import { sendEmail } from "../utils/email";
import { v4 as uuidv4 } from "uuid";
import { generateAccessToken, generateRefreshToken } from "../utils/auth";
import { AuthRequest } from "../middlewares/authMiddleware";

export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, role } = req.body;

    // validate role
    const validRoles = ["user", "admin"];
    if (!role || !validRoles.includes(role)) {
      res.status(400).json({ message: "invalid role specified" });
      return;
    }

    //check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({ message: "User already exists" });
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role: role || "user",
    });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Find user and check password
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(400).json({ message: "Invalid credentials" });
      return;
    }

    const accessToken = generateAccessToken(String(user._id));
    const refreshToken = generateRefreshToken(String(user._id));

    user.refreshTokens?.push(refreshToken);
    await user.save();

    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: true });
    res.json({ accessToken });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const sendMfaOtp = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const otp = speakeasy.totp({
      secret: process.env.OTP_SECRET!,
      digits: 6,
      step: 300, // OTP valid for 5 minutes
    });

    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 5 * 60 * 1000); // Expires in 5 min
    await user.save();

    await sendEmail(user.email, "Your OTP Code", `Your OTP is: ${otp}`);

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const verifyMfaOtp = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user || !user.otp || !user.otpExpires) {
      res.status(400).json({ message: "Invalid or expired OTP" });
      return;
    }

    if (Date.now() > new Date(user.otpExpires).getTime()) {
      res.status(400).json({ message: "OTP expired" });
      return;
    }

    if (user.otp !== req.body.otp) {
      res.status(400).json({ message: "Incorrect OTP" });
      return;
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: "MFA verification successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const sendVerificationEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    if (user.isVerified) {
      res.status(400).json({ message: "Email already verified" });
      return;
    }

    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${user.emailVerificationToken}`;

    await sendEmail(
      user.email,
      "Verify Your Email",
      `Click here to verify: ${verificationLink}`
    );

    res.json({ message: "Verification email sent" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({
      emailVerificationToken: req.query.token,
    });

    if (!user) {
      res.status(400).json({ message: "Invalid or expired token" });
      return;
    }

    user.isVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();

    res.json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const sendPasswordResetEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    user.resetPasswordToken = uuidv4();
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${user.resetPasswordToken}`;

    await sendEmail(
      user.email,
      "Reset Your Password",
      `Click here to reset: ${resetLink}`
    );

    res.json({ message: "Password reset email sent" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.body.token,
      resetPasswordExpires: { $gt: new Date() }, // Ensure token is not expired
    });

    if (!user) {
      res.status(400).json({ message: "Invalid or expired token" });
      return;
    }

    user.password = req.body.newPassword; // Will be hashed due to pre-save middleware
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    res.status(401).json({ message: "No refresh token provided" });
    return;
  }

  try {
    const decoded: any = jwt.verify(refreshToken, process.env.REFRESH_SECRET!);
    const user = await User.findById(decoded.userId);

    if (!user || !user.refreshTokens?.includes(refreshToken)) {
      res.status(403).json({ message: "Invalid refresh token" });
      return;
    }

    const newAccessToken = generateAccessToken(String(user._id));
    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).json({ message: "Invalid or expired refresh token" });
  }
};

export const logout = async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?.id);
    if (!user) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    user.refreshTokens = user.refreshTokens?.filter(
      (token) => token !== req.cookies.refreshToken
    );
    await user.save();

    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};
