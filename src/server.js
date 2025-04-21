import dotenv from "dotenv";
import connectDB from "./db/db.connect.js";
import app from "./app.js";
import asyncHandler from "./utils/async-handler.js";

dotenv.config({
  path: "../.env",
});

const PORT = process.env.PORT || 8080;

const startServer = asyncHandler(async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`✅ Server is running on port ${PORT}`);
  });
});

startServer();
