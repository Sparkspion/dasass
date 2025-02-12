import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

export interface IUser {
  username: string;
  email: string;
  password: string;
  role: "user" | "admin";
  avatar: string;
  isDeleted: boolean;
  otp?: string;
  otpExpires?: Date;
  isVerified?: boolean;
  emailVerificationToken?: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  refreshTokens?: string[];
  comparePassword: (str: string) => boolean;
}

const userSchema: Schema<IUser> = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    avatar: { type: String, default: "" },
    isDeleted: { type: Boolean, default: false },
    otp: { type: String },
    otpExpires: { type: Date },
    isVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, default: () => uuidv4() },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    refreshTokens: [{ type: String }],
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = async function (enteredPassword: string) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model("User", userSchema);
export default User;
