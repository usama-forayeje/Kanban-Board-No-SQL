import express from "express";
import healthCheckRoute from "./routes/healthCheck.route.js";
import cookieParser from "cookie-parser";
import authRoutes from './routes/auth.route.js'
import cors from 'cors'
import { errorHandler } from "./middlewares/errorHandler.middleware.js";
const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(errorHandler);

app.use(
  cors({
    origin: "localhost:8000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Accept"],
    exposedHeaders: ["Set-Cookie", "*"],
  })
);

app.use("/api/v1/healthCheck", healthCheckRoute);

app.use("/api/v1/auth", authRoutes);

export default app;
