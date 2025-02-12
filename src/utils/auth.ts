import jwt from "jsonwebtoken";

const generateAccessToken = (userId: string) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: "15m" });
};

const generateRefreshToken = (userId: string) => {
  return jwt.sign({ userId }, process.env.REFRESH_SECRET!, { expiresIn: "7d" });
};

export { generateAccessToken, generateRefreshToken };
