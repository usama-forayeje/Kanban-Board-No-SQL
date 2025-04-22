import asyncHandler from "../utils/async-handler.js";

// Auth system
const singUp = asyncHandler(async (req, res) => {});

const singIn = asyncHandler(async (req, res) => {});

const verifyUser = asyncHandler(async (req, res) => {});

const singOut = asyncHandler(async (req, res) => {});

const refreshToken = asyncHandler(async (req, res) => {});

const socialLogin = asyncHandler(async (req, res) => {});

const twoFactorAuth = asyncHandler(async (req, res) => {});

// password reset system
const forgotPassword = asyncHandler(async (req, res) => {});

const resetPassword = asyncHandler(async (req, res) => {});

const changePassword = asyncHandler(async (req, res) => {});

// User system
const userProfile = asyncHandler(async (req, res) => {});

const updateProfile = asyncHandler(async (req, res) => {});

const deleteAccount = asyncHandler(async (req, res) => {});

const updateUserRole = asyncHandler(async (req, res) => {});

const logoutAllDevices = asyncHandler(async (req, res) => {});

const updateNotificationSettings = asyncHandler(async (req, res) => {});

// Admin system
const getAllUsers = asyncHandler(async (req, res) => {});

const getSingleUser = asyncHandler(async (req, res) => {});

const deleteUser = asyncHandler(async (req, res) => {});

const banUser = asyncHandler(async (req, res) => {});

const unBanUser = asyncHandler(async (req, res) => {});

// Device system
const getLoginLogs = asyncHandler(async (req, res) => {});

const getDeviceList = asyncHandler(async (req, res) => {});

export {
  singUp,
  singIn,
  singOut,
  forgotPassword,
  resetPassword,
  userProfile,
  verifyUser,
  updateProfile,
  changePassword,
  deleteAccount,
  refreshToken,
  socialLogin,
  twoFactorAuth,
  getAllUsers,
  getSingleUser,
  deleteUser,
  banUser,
  getLoginLogs,
  getDeviceList,
  updateUserRole,
  unBanUser,
  logoutAllDevices,
  updateNotificationSettings,
};
