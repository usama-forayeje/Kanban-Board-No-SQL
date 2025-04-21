import express from "express";
import healthCheckRoute from "./routes/healthCheck.route.js";
const app = express();

app.use("/api/v1/healthCheck", healthCheckRoute);

export default app;
