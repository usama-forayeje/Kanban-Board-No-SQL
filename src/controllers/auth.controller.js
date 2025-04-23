import { AvailableUserRoles, UserRolesEnum } from "../constants/roles.js";
import { User } from "../models/users.models.js";
import { ApiResponse } from "../utils/api-response.js";
import asyncHandler from "../utils/async-handler.js";
import { generateTokens } from "../utils/jwt.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { sendMail, verificationMailGenContent } from "../utils/mail.js";
import { ApiError } from "../utils/api-errors.js";
import { UAParser } from "ua-parser-js";
import { generateOTP } from "../constants/generateOTP.js";

// Auth system
const signUp = asyncHandler(async (req, res) => {
  const { email, userName, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError(409, "User already exists with this email.");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const unHashedToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");

  const expiryTime = new Date(Date.now() + 30 * 60 * 1000); // 30 mins

  const user = await User.create({
    email,
    userName,
    displayName: userName,
    password: hashedPassword,
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpiry: expiryTime,
    role: UserRolesEnum.MEMBER,
  });

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
});

const verifyUser = asyncHandler(async (req, res) => {
  const rawToken = req.params.emailVerificationToken;

  if (!rawToken) {
    return res.status(400).json(new ApiResponse(400, "Verification token is required"));
  }

  const hashedToken = crypto.createHash("sha256").update(rawToken).digest("hex");

  const user = await User.findOne({ emailVerificationToken: hashedToken });

  if (!user) {
    return res.status(400).json(new ApiResponse(400, "Invalid or expired verification token"));
  }

  if (user.emailVerificationTokenExpiry < Date.now()) {
    return res.status(400).json(new ApiResponse(400, "Verification token has expired"));
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpiry = undefined;

  await user.save();

  return res.status(200).json(new ApiResponse(200, "Email verified successfully"));
});

const signIn = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // 1️⃣ Find user
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(401, "User not found with this email.");
  }

  const isPasswordMatch = bcrypt.compare(password, user.password);

  if (!isPasswordMatch) {
    throw new ApiError(401, "Password is incorrect.");
  }

  // 3️⃣ Check if email is verified
  if (!user.isEmailVerified) {
    throw new ApiError(401, "Email is not verified.");
  }

  // 4️⃣ Generate tokens
  const { accessToken, refreshToken } = await generateTokens(user);

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
    secure: false,
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
});

const signOut = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(200).json(new ApiResponse(200, "Already signed out"));
  }

  const user = await User.findOne({ refreshToken });

  if (user) {
    user.refreshToken = null;
    user.refreshTokenExpiry = null; // if you store expiry
    await user.save({ validateBeforeSave: false });
  }

  // 🍪 Clear refreshToken cookie
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    expires: new Date(0),
  });

  return res.status(200).json(new ApiResponse(200, "User signed out successfully"));
});

const refreshToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    throw new ApiError(401, "🔒 Refresh token missing. Please log in again.");
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    throw new ApiError(403, "⛔ Invalid or expired refresh token.");
  }

  const user = await User.findById(decoded._id);

  if (!user || user.refreshToken !== refreshToken) {
    throw new ApiError(403, "⛔ Refresh token mismatch.");
  }

  const accessToken = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "15m",
  });

  return res.status(200).json(new ApiResponse(200, "✅ Token refreshed", { accessToken }));
});

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
});

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

  await user.save({ validateBeforeSave: false });

  await sendMail({
    email: user.email,
    subject: "🔐 Your Otp Code",
    text: `Your OTP code is ${otp}. It is valid for 5 minutes.`,
  });
});

const verifyOTP = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const userId = req.user._id;

  const user = await User.findById(userId);

  if (!user || user.otp !== otp) {
    throw new ApiError(401, "Invalid OTP.");
  }

  user.otp = undefined;
  user.otpExpiry = undefined;
  user.isTowFactorVerified = true;

  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Tow factor authentication verified successfully."));
});

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

  const resetToken = crypto.randomBytes(32).toString("hex");

  user.forgotPasswordToken = resetToken;
  user.forgotPasswordTokenExpiry = Date.now() + 60 * 60 * 1000; // 1 hour

  await user.save({ validateBeforeSave: false });

  // 👉 Send reset password email here
  const resetURL = `${process.env.BASE_URL}/reset-password/${resetToken}`;
  const mailContent = await forgotPasswordMailGenContent(user.userName, resetURL);

  await sendMail({
    email: user.email,
    subject: "🔁 Reset Your Password",
    mailgenContent: mailContent,
  });

  return res.status(200).json(new ApiResponse(200, "Password reset link sent to email."));
});

const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { forgotPasswordToken } = req.params;

  if (!forgotPasswordToken || !password) {
    throw new ApiError(400, "Reset token and new password are required.");
  }

  // 🔐 Hash the token to match with DB
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
  user.password = await bcrypt.hash(password, 10);

  // 🔄 Clear reset token & expiry
  user.forgotPasswordToken = undefined;
  user.forgotPasswordTokenExpiry = undefined;

  // 💾 Save updated user without extra validations
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(new ApiResponse(200, "✅ Password has been reset successfully."));
});

const changePassword = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(userId).select("+password");

  if (!user) {
    throw new ApiError(404, "❌ User not found.");
  }

  const isOldPasswordCorrect = bcrypt.compare(oldPassword, user.password);
  if (!isOldPasswordCorrect) {
    throw new ApiError(401, "⛔ Old password is incorrect.");
  }

  const isSamePassword = bcrypt.compare(newPassword, user.password);
  if (isSamePassword) {
    throw new ApiError(400, "❌ New password are same old password.");
  }

  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(newPassword, salt);
  user.passwordChangedAt = new Date();

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, "🔐 Password changed successfully. Please login again."));
});

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
