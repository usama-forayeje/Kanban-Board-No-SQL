import dotenv from "dotenv";
import connectDB from "../config/db.js";
import app from "./app.js";
import { logger } from "./utils/logger.js";

dotenv.config({
  path: "./.env",
});

const PORT = process.env.PORT || 8080;

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => {
      logger.info("🔗 Connected to the database successfully");
      logger.success(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    logger.error("❎ Failed to connect to the database");
  }
};

startServer();
