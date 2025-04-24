import { UserRolesEnum } from "../constants/roles.js";
import { User } from "../models/users.models.js";
import { ApiResponse } from "../utils/api-response.js";
import asyncHandler from "../utils/async-handler.js";
import { generateTokens } from "../utils/jwt.js";
import crypto from "crypto";
import {
  forgotPasswordMailGenContent,
  sendMail,
  twoFactorAuthMailGenContent,
  verificationMailGenContent,
} from "../utils/mail.js";
import { ApiError } from "../utils/api-errors.js";
import { UAParser } from "ua-parser-js";
import { generateOTP } from "../constants/generateOTP.js";
import { logger } from "../utils/logger.js";

// Auth system
const signUp = asyncHandler(async (req, res) => {
  const { email, userName, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError(409, "User already exists with this email.");
  }

  const user = new User({
    email,
    userName,
    displayName: userName,
    password,
    role: UserRolesEnum.MEMBER,
  });

  // 🔐 Generate verification token using method
  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationTokenExpiry = tokenExpiry;

  await user.save();

  // ✅ CALL verificationMailGenContent here
  const mailContent = await verificationMailGenContent(
    user.userName,
    `${process.env.BASE_URL}/verify/${unHashedToken}`
  );

  // ✅ Send verification email
  await sendMail({
    email: user.email,
    subject: "Verify your email address",
    mailgenContent: mailContent,
  });

  const { accessToken, refreshToken } = await generateTokens(user);

  return res.status(201).json(
    new ApiResponse(201, "User created successfully", {
      _id: user._id,
      email: user.email,
      userName: user.userName,
      displayName: user.displayName,
      role: user.role,
      tokens: {
        accessToken,
        refreshToken,
      },
    })
  );
}); // ok

const verifyUser = asyncHandler(async (req, res) => {
  const rawToken = req.params.emailVerificationToken;

  if (!rawToken) {
    return res.status(400).json(new ApiResponse(400, "Verification token is required"));
  }

  const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json(new ApiResponse(400, "Invalid or expired verification token"));
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpiry = undefined;

  await user.save();

  return res.status(200).json(new ApiResponse(200, "Email verified successfully"));
}); //ok

const signIn = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // 1️⃣ Find user
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(401, "User not found with this email.");
  }
  // 2️⃣ Check password match
  const isPasswordMatch = await user.isPasswordMatch(password);
  if (!isPasswordMatch) {
    throw new ApiError(401, "Password is incorrect.");
  }

  // 3️⃣ Check if email is verified
  if (!user.isEmailVerified) {
    throw new ApiError(401, "Email is not verified.");
  }

  // 4️⃣ Generate tokens
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  // 5️⃣ Save refreshToken + audit logs
  const parser = new UAParser(req.headers["user-agent"]);
  const uaResult = parser.getResult();

  const ip =
    req.headers["x-forwarded-for"]?.split(",")?.[0]?.trim() ||
    req.socket?.remoteAddress ||
    "Unknown";

  user.refreshToken = refreshToken;
  user.lastLoginAt = new Date();
  user.lastLoginMeta = {
    ip,
    userAgent: req.headers["user-agent"],
    browser: `${uaResult.browser.name || "Unknown"} ${uaResult.browser.version || ""}`,
    os: `${uaResult.os.name || "Unknown"} ${uaResult.os.version || ""}`,
    device: uaResult.device?.type || "Desktop",
  };

  await user.save({ validateBeforeSave: false });

  // 6️⃣ Set refreshToken as cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Secure cookies in production
    sameSite: "Strict",
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });

  // 7️⃣ Send success response
  return res.status(200).json(
    new ApiResponse(200, "User signed in successfully", {
      _id: user._id,
      userName: user.userName,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      tokens: {
        accessToken,
        refreshToken,
      },
    })
  );
}); // ok

const signOut = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;

  // Check if there's a token in the cookie
  if (!refreshToken) {
    return res.status(200).json(new ApiResponse(200, "Already signed out"));
  }

  const user = await User.findOne({ refreshToken });

  if (user) {
    // Clear the refresh token from the user's data
    user.refreshToken = null;
    await user.save({ validateBeforeSave: false });
  }

  // Clear refreshToken and accessToken cookies
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Ensure this is set correctly for production
    sameSite: "Strict",
    expires: new Date(0),
  });

  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Ensure this is set correctly for production
    sameSite: "Strict",
    expires: new Date(0),
  });

  return res.status(200).json(new ApiResponse(200, "User signed out successfully"));
}); // ok

const refreshToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;
  logger.info("Refresh token from cookie:", refreshToken);
  if (!refreshToken) {
    throw new ApiError(401, "🔒 Refresh token missing. Please log in again.");
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    throw new ApiError(403, "⛔ Invalid or expired refresh token.");
  }
  logger.info("decoded refresh token: " + decoded);
  const user = await User.findById(decoded._id);

  if (!user) {
    throw new ApiError(404, "❌ User not found.");
  }

  if (user.refreshToken !== refreshToken) {
    throw new ApiError(403, "⛔ Refresh token mismatch.");
  }

  const accessToken = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "15m",
  });

  return res.status(200).json(new ApiResponse(200, "✅ Token refreshed", { accessToken }));
}); // Problematic

const socialLogin = asyncHandler(async (req, res) => {
  const { email, displayName, profileImage, provider } = req.body;

  // 1️⃣ Basic validation
  if (!email || !displayName || !provider) {
    throw new ApiError(400, "Missing required social login fields");
  }

  // 2️⃣ Check if user already exists
  let user = await User.findOne({ email });

  if (!user) {
    user = await User.create({
      email,
      displayName,
      profileImage: profileImage || "",
      provider,
      isEmailVerified: true, // Social login emails are usually verified
      userName: email.split("@")[0], // Generate a default username
    });
  }

  // 4️⃣ Generate tokens
  const { accessToken, refreshToken } = await generateTokens(user);

  // 5️⃣ Save refreshToken and update login info
  user.refreshToken = refreshToken;
  user.lastLoginAt = new Date();
  await user.save({ validateBeforeSave: false });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: false, // 🔐 production e true koro (HTTPS only)
    sameSite: "Strict",
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });

  // 7️⃣ Success response
  return res.status(200).json(
    new ApiResponse(200, "User logged in via social provider successfully", {
      _id: user._id,
      userName: user.userName,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      profileImage: user.profileImage,
      tokens: {
        accessToken,
        refreshToken,
      },
    })
  );
}); // ok

const twoFactorAuth = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found.");
  }

  const otp = generateOTP();
  const otpExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes

  user.otp = otp;
  user.otpExpiry = otpExpiry;

  const { unHashedToken } = user.generateTemporaryToken();

  await user.save({ validateBeforeSave: false });

  const mailContent = await twoFactorAuthMailGenContent(user.userName, otp);

  await sendMail({
    email: user.email,
    subject: "🔐 Two-factor Authentication OTP",
    mailgenContent: mailContent,
  });

  return res.status(200).json(new ApiResponse(200, "OTP sent to email.", { otp, unHashedToken }));
}); // ok

const verifyOTP = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const userId = req.user._id;

  const user = await User.findById(userId);

  if (!user || user.otp !== otp) {
    throw new ApiError(401, "Invalid OTP.");
  }

  user.otp = undefined;
  user.otpExpiry = undefined;
  user.isTwoFactorVerified = true;

  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Tow factor authentication verified successfully."));
}); // ok

// password  system
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "User not found with this email.");
  }

  if (!user.isEmailVerified) {
    throw new ApiError(401, "Email is not verified.");
  }

  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordTokenExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // 👉 Send reset password email here
  const resetURL = `${process.env.BASE_URL}/reset-password/${unHashedToken}`;
  const mailContent = await forgotPasswordMailGenContent(user.userName, resetURL);

  await sendMail({
    email: user.email,
    subject: "🔁 Reset Your Password",
    mailgenContent: mailContent,
  });

  return res.status(200).json(new ApiResponse(200, "Password reset link sent to email."));
}); // ok

const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { forgotPasswordToken } = req.params;

  if (!forgotPasswordToken || !password) {
    throw new ApiError(400, "Reset token and new password are required.");
  }

  const hashedToken = crypto.createHash("sha256").update(forgotPasswordToken).digest("hex");

  // 🔎 Find user with valid token
  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, "⛔ Invalid or expired reset token.");
  }

  // 🔑 Hash the new password
  user.password = password;

  // 🔄 Clear reset token & expiry
  user.forgotPasswordToken = undefined;
  user.forgotPasswordTokenExpiry = undefined;

  // 💾 Save updated user without extra validations
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(new ApiResponse(200, "✅ Password has been reset successfully."));
}); // ok

const changePassword = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(userId).select("+password");

  if (!user) {
    throw new ApiError(404, "❌ User not found.");
  }

  const isOldPasswordCorrect = await user.isPasswordMatch(oldPassword);
  if (!isOldPasswordCorrect) {
    throw new ApiError(401, "⛔ Old password is incorrect.");
  }

  const isSamePassword = await user.isPasswordMatch(newPassword);
  if (isSamePassword) {
    throw new ApiError(400, "❌ New password are same old password.");
  }

  user.password = newPassword;
  user.passwordChangedAt = new Date();

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, "🔐 Password changed successfully. Please login again."));
}); // ok

export {
  signUp,
  signIn,
  signOut,
  forgotPassword,
  resetPassword,
  verifyUser,
  verifyOTP,
  changePassword,
  refreshToken,
  socialLogin,
  twoFactorAuth,
};
