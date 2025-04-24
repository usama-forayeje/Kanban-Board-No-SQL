
import { validationResult } from "express-validator";
import { logger } from "../utils/logger.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = errors.array().map((err) => ({
    field: err.param,
    message: err.msg,
    location: err.location,
  }));

  logger.error("🔴 Validation Error:", {
    path: req.originalUrl,
    method: req.method,
    errors: extractedErrors,
  });

  return res.status(422).json({
    name: "ApiError",
    statusCode: 422,
    error: extractedErrors,
    success: false,
  });
  
};
