import asyncHandler from "../utils/async-handler.js";

// User system
const userProfile = asyncHandler(async (req, res) => {});

const updateProfile = asyncHandler(async (req, res) => {});

const deleteAccount = asyncHandler(async (req, res) => {});

const updateUserRole = asyncHandler(async (req, res) => {});

const logoutAllDevices = asyncHandler(async (req, res) => {});

const updateNotificationSettings = asyncHandler(async (req, res) => {});

export{userProfile, updateProfile, deleteAccount, updateUserRole, logoutAllDevices, updateNotificationSettings}