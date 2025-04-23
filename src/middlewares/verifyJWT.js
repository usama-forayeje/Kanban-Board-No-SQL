import jwt from "jsonwebtoken"; // এইটা লাগবেই!
import { User } from "../models/users.models.js";
import { ApiError } from "../utils/api-errors.js";
import asyncHandler from "../utils/async-handler.js";

const verifyJWT = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new ApiError(401, "Unauthorized - No token provided"));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded._id).select("-password");

    if (!req.user) {
      return next(new ApiError(401, "Unauthorized - User not found"));
    }

    next();
  } catch (error) {
    console.log("JWT Verification Error:", error.message);
    return next(new ApiError(401, "Unauthorized - Invalid token"));
  }
});

export { verifyJWT };
