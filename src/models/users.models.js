import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { AvailableUserRoles, UserRolesEnum } from "../constants/roles.js";
import { AvailableUserStatuses, userStatusEnum } from "../constants/status.js";

// User Schema Definition
const UserSchema = new Schema(
  {
    avatar: {
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: "placeholder.com/150",
        localPath: "",
      },
    },
    role: {
      type: String,
      enum: AvailableUserRoles,
      default: UserRolesEnum.MEMBER,
    },
    status: {
      type: String,
      enum: AvailableUserStatuses,
      default: userStatusEnum.ACTIVE,
    },
    userName: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: (v) => /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/.test(v),
        message: "Invalid email address format",
      },
    },
    phoneNumber: {
      type: Number,
    },
    displayName: {
      type: String,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    otp: {
      type: String,
      default: null,
    },
    otpExpires: {
      type: Date,
      default: null,
    },
    isTwoFactorVerified: {
      type: Boolean,
      default: false,
    },
    lastLoginAt: {
      type: Date,
      default: null,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    forgotPasswordToken: {
      type: String,
      default: null,
    },
    forgotPasswordTokenExpiry: {
      type: Date,
      default: null,
    },
    refreshToken: {
      type: String,
      default: null,
    },
    refreshTokenExpiry: {
      type: Date,
      default: null,
    },
    emailVerificationToken: {
      type: String,
      default: null,
    },
    emailVerificationTokenExpiry: {
      type: Date,
      default: null,
    },
    provider: {
      type: String,
      enum: ["google", "facebook", "github", "local"],
      default: "local",
    },
  },
  { timestamps: true }
);

// Pre-save hook to hash the password
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next(); // Only hash if password is modified
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    return next(err);
  }
});

// // Instance method to check password match
// UserSchema.methods.isPasswordMatch = async function (password) {
//   return await bcrypt.compare(password, this.password);
// };

// // Method to generate access token
// UserSchema.methods.generateAccessToken = function () {
//   return jwt.sign({ _id: this._id, role: this.role }, process.env.JWT_SECRET, {
//     expiresIn: process.env.JWT_EXPIRES_IN || "1h", // Default expiration to 1 hour if not set
//   });
// };

// // Method to generate refresh token
// UserSchema.methods.generateRefreshToken = function () {
//   return jwt.sign({ _id: this._id, role: this.role }, process.env.REFRESH_TOKEN_SECRET, {
//     expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d", // Default expiration to 7 days
//   });
// };

// // Method to generate temporary token (for email verification, forgot password, etc.)
// UserSchema.methods.generateTemporaryToken = function () {
//   const unHashedToken = crypto.randomBytes(20).toString("hex");

//   const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");

//   const tokenExpiry = Date.now() + 20 * 60 * 1000; // 20 minutes

//   return {
//     unHashedToken,
//     hashedToken,
//     tokenExpiry,
//   };
// };

// Export User Model
export const User = mongoose.model("User", UserSchema);
