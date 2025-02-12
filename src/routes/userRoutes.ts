import express from "express";
import { authenticateUser, authorizeRole } from "../middlewares/authMiddleware";
import {
  deleteUser,
  getAllUsers,
  getUserById,
  getUserProfile,
  restoreUser,
  softDeleteUser,
  updateUser,
  updateUserProfile,
} from "../controllers/userController";
import { upload } from "../middlewares/uploadMiddleware";

const router = express.Router();

router.get("/profile", authenticateUser, getUserProfile);
router.put(
  "/profile",
  authenticateUser,
  (req, res, next) => {
    upload.single("avatar")(req, res, (err) => {
      if (err) {
        return res.status(400).json({
          success: false,
          message: err.message || "Image upload failed",
          error: process.env.NODE_ENV === "development" ? err : {},
        });
      }
      next();
    });
  },
  updateUserProfile
);

// Admin Routes
router.get("/", authenticateUser, authorizeRole(["admin"]), getAllUsers);
router.get("/:id", authenticateUser, authorizeRole(["admin"]), getUserById);
router.put("/:id", authenticateUser, authorizeRole(["admin"]), updateUser);
router.delete(
  "/:id/remove",
  authenticateUser,
  authorizeRole(["admin"]),
  deleteUser
);
router.delete(
  "/:id",
  authenticateUser,
  authorizeRole(["admin"]),
  softDeleteUser
);
router.put(
  "/:id/restore",
  authenticateUser,
  authorizeRole(["admin"]),
  restoreUser
);

export default router;
