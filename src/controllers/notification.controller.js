import asyncHandler from "../utils/async-handler.js";

const createNotification = asyncHandler(async (req, res) => {});

const getAllNotificationsByUser = asyncHandler(async (req, res) => {});

const markNotificationAsRead = asyncHandler(async (req, res) => {});

const markAllNotificationsAsRead = asyncHandler(async (req, res) => {});

const deleteNotification = asyncHandler(async (req, res) => {});

const clearAllReadNotifications = asyncHandler(async (req, res) => {});

const getUnreadNotificationCount = asyncHandler(async (req, res) => {});

export {
  clearAllReadNotifications,
  createNotification,
  getAllNotificationsByUser,
  markAllNotificationsAsRead,
  markNotificationAsRead,
  deleteNotification,
  getUnreadNotificationCount,
};
