import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import logger from "./utils/logger";
import mongoose from "mongoose";
import { errorHandler } from "./middlewares/errorHandler";
import authRoutes from "./routes/authRoutes";
import userRoutes from "./routes/userRoutes";
import healthRoute from "./routes/healthRoute";
import mongoSanitize from "express-mongo-sanitize";
import hpp from "hpp";

dotenv.config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(errorHandler);
app.use(
  morgan("combined", {
    stream: {
      write: (msg) => logger.info(msg.trim()),
    },
  })
);
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/health", healthRoute);
app.use("/uploads", express.static("uploads"));
app.use(mongoSanitize()); // Prevents NoSQL injection
app.use(hpp()); // Prevents HTTP Parameter Pollution

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI as string)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.get("/", (req, res) => {
  res.send("Server is running!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
