import asyncHandler from "../utils/async-handler.js";

const createTask = asyncHandler(async (req, res) => {});

const getAllTasksByProject = asyncHandler(async (req, res) => {});

const getSingleTask = asyncHandler(async (req, res) => {});

const updateTask = asyncHandler(async (req, res) => {});

const deleteTask = asyncHandler(async (req, res) => {});

const reorderTasks = asyncHandler(async (req, res) => {});

const uploadAttachment = asyncHandler(async (req, res) => {});

const assignTask = asyncHandler(async (req, res) => {});

const changeStatus = asyncHandler(async (req, res) => {});

const getTaskStatsByProject = asyncHandler(async (req, res) => {});

const sendTaskReminder = asyncHandler(async (req, res) => {});

const getRecentUpdatedTasks = asyncHandler(async (req, res) => {});

const searchTasks = asyncHandler(async (req, res) => {});

export {
  createTask,
  getAllTasksByProject,
  getRecentUpdatedTasks,
  getSingleTask,
  updateTask,
  deleteTask,
  reorderTasks,
  uploadAttachment,
  assignTask,
  changeStatus,
  getTaskStatsByProject,
  sendTaskReminder,
  searchTasks,
};
