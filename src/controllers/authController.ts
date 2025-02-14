import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import speakeasy from 'speakeasy';
import { sendEmail } from '../utils/email';
import { v4 as uuidv4 } from 'uuid';
import { generateAccessToken, generateRefreshToken } from '../utils/auth';
import { AuthRequest } from '../middlewares/authMiddleware';
import {
  ALL_ROLES,
  COOKIE,
  HTTP_STATUS,
  OTP_DIGITS,
  OTP_DURATION,
  OTP_EXPIRY_DURATION,
  ROLES,
  SALT,
} from '../base/const';
import MESSAGE from '../base/messages';

export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, role } = req.body;

    // validate role
    if (!role || !ALL_ROLES.includes(role)) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.INVALID_ROLE });
      return;
    }

    //check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.USER_EXISTS });
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT);

    // Create user
    const newUser = {
      username,
      email,
      password: hashedPassword,
      role: role || ROLES.USER,
    };
    const user = new User(newUser);
    await user.save();

    res.status(HTTP_STATUS.CREATED).json({ message: MESSAGE.USER_REGISTERED });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Find user and check password
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.INVALID_CREDENTIALS });
      return;
    }

    const accessToken = generateAccessToken(String(user._id));
    const refreshToken = generateRefreshToken(String(user._id));

    user.refreshTokens?.push(refreshToken);
    await user.save();

    res.cookie(COOKIE.REFRESH_TOKEN, refreshToken, {
      httpOnly: true,
      secure: true,
    });
    res.json({ accessToken });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const sendMfaOtp = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res
        .status(HTTP_STATUS.NOT_FOUND)
        .json({ message: MESSAGE.USER_NOT_FOUND });
      return;
    }

    const otp = speakeasy.totp({
      secret: process.env.OTP_SECRET!,
      digits: OTP_DIGITS,
      step: OTP_DURATION,
    });

    user.otp = otp;
    user.otpExpires = new Date(Date.now() + OTP_EXPIRY_DURATION);
    await user.save();

    await sendEmail(user.email, 'Your OTP Code', `Your OTP is: ${otp}`);

    res.json({ message: MESSAGE.OTP_SENT });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const verifyMfaOtp = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user || !user.otp || !user.otpExpires) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.OTP_INVALID_OR_EXPIRED });
      return;
    }

    if (Date.now() > new Date(user.otpExpires).getTime()) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.OTP_EXPIRED });
      return;
    }

    if (user.otp !== req.body.otp) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: MESSAGE.OTP_INVALID });
      return;
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'MFA verification successful' });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const sendVerificationEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res
        .status(HTTP_STATUS.NOT_FOUND)
        .json({ message: MESSAGE.USER_NOT_FOUND });
      return;
    }

    if (user.isVerified) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: 'Email already verified' });
      return;
    }

    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${user.emailVerificationToken}`;

    await sendEmail(
      user.email,
      'Verify Your Email',
      `Click here to verify: ${verificationLink}`
    );

    res.json({ message: 'Verification email sent' });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({
      emailVerificationToken: req.query.token,
    });

    if (!user) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: 'Invalid or expired token' });
      return;
    }

    user.isVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();

    res.json({ message: MESSAGE.EMAIL_VERIFIED });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const sendPasswordResetEmail = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      res
        .status(HTTP_STATUS.NOT_FOUND)
        .json({ message: MESSAGE.USER_NOT_FOUND });
      return;
    }

    user.resetPasswordToken = uuidv4();
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${user.resetPasswordToken}`;

    await sendEmail(
      user.email,
      'Reset Your Password',
      `Click here to reset: ${resetLink}`
    );

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.body.token,
      resetPasswordExpires: { $gt: new Date() }, // Ensure token is not expired
    });

    if (!user) {
      res
        .status(HTTP_STATUS.BAD_REQUEST)
        .json({ message: 'Invalid or expired token' });
      return;
    }

    user.password = req.body.newPassword; // Will be hashed due to pre-save middleware
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    res
      .status(HTTP_STATUS.UNAUTHORIZED)
      .json({ message: 'No refresh token provided' });
    return;
  }

  try {
    const decoded: any = jwt.verify(refreshToken, process.env.REFRESH_SECRET!);
    const user = await User.findById(decoded.userId);

    if (!user || !user.refreshTokens?.includes(refreshToken)) {
      res
        .status(HTTP_STATUS.FORBIDDEN)
        .json({ message: 'Invalid refresh token' });
      return;
    }

    const newAccessToken = generateAccessToken(String(user._id));
    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res
      .status(HTTP_STATUS.FORBIDDEN)
      .json({ message: 'Invalid or expired refresh token' });
  }
};

export const logout = async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?.id);
    if (!user) {
      res
        .status(HTTP_STATUS.UNAUTHORIZED)
        .json({ message: MESSAGE.USER_NOT_FOUND });
      return;
    }

    user.refreshTokens = user.refreshTokens?.filter(
      (token) => token !== req.cookies.refreshToken
    );
    await user.save();

    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res
      .status(HTTP_STATUS.SERVER_ERROR)
      .json({ message: MESSAGE.SERVER_ERROR });
  }
};
