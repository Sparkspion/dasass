import rateLimit from "express-rate-limit";

// Limits requests to prevent brute-force attacks
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 login attempts per 15 minutes
  message: "Too many login attempts. Try again later.",
  headers: true,
});

export const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Max 100 requests per minute
  message: "Too many requests. Please slow down.",
  headers: true,
});
