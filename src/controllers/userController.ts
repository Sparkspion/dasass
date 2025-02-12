import { NextFunction, Request, Response } from "express";
import bcrypt from "bcryptjs";
import User from "../models/User";
import { AuthRequest } from "../middlewares/authMiddleware";
import cloudinary from "../config/cloudinary";

export const getUserProfile = async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?.id).select("-password");
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const updateUserProfile = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await User.findById(req.user?.id);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    console.log("logging...", user, req.file, req.body);
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    if (req.file) {
      //   user.avatar = `/uploads/${req.file.filename}`;
      const result = await cloudinary.uploader.upload(req.file.path);
      user.avatar = result.secure_url;
    }

    await user.save();

    res.json({ message: "Profile updated successfully", user });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
    next(error);
  }
};

// GET all users with pagination (Admin only)
export const getAllUsers = async (req: Request, res: Response) => {
  try {
    const page = Number(req.query.page) || 1; // Default: Page 1
    const limit = Number(req.query.limit) || 10; // Default: 10 users per page
    const skip = (page - 1) * limit;

    const searchQuery = req.query.search ? (req.query.search as string) : "";
    const roleFilter = req.query.role ? (req.query.role as string) : "";
    const sortBy = req.query.sortBy
      ? (req.query.sortBy as string)
      : "createdAt"; // Default: sort by createdAt
    const sortOrder = req.query.sortOrder === "asc" ? 1 : -1; // Default: descending order

    const query: any = {};

    // Search by username or email (case-insensitive)
    if (searchQuery) {
      query.$or = [
        { username: { $regex: searchQuery, $options: "i" } },
        { email: { $regex: searchQuery, $options: "i" } },
      ];
    }

    // Filter by role
    if (roleFilter) {
      query.role = roleFilter;
    }

    const users = await User.find(query)
      .select("-password")
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit);

    const totalUsers = await User.countDocuments(query);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({ users, page, totalPages, totalUsers });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// GET single user by ID (Admin only)
export const getUserById = async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// UPDATE user (Admin only)
export const updateUser = async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    user.role = req.body.role || user.role; // Admin can update roles

    await user.save();
    res.json({ message: "User updated successfully", user });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// DELETE user (Admin only)
export const deleteUser = async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    await user.deleteOne();
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// Soft delete user (Admin only)
export const softDeleteUser = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ message: "User soft deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// Restore soft deleted user (Admin only)
export const restoreUser = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(
      id,
      { isDeleted: false },
      { new: true }
    );

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ message: "User restored successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const updateUserPassword = async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?.id);

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      res
        .status(400)
        .json({ message: "Both current and new passwords are required" });
      return;
    }

    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      res.status(401).json({ message: "Incorrect current password" });
      return;
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};
