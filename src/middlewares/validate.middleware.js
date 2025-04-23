import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-errors.js";


export const validate = (req, res, next) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = errors.array().map((err) => ({
    field: err.param,
    message: err.msg,
    location: err.location, // e.g., 'body', 'query', 'params'
  }));

  console.error("🔴 Validation Error:", {
    path: req.originalUrl,
    method: req.method,
    errors: extractedErrors,
  });

  return next(
    new ApiError(422, "Validation Error", {
      validationErrors: extractedErrors,
    })
  );
};
