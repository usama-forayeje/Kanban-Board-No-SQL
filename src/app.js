import express from "express";
import healthCheckRoute from "./routes/healthCheck.route.js";
import cookieParser from "cookie-parser";
import cors from 'cors'
const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

export default app;
