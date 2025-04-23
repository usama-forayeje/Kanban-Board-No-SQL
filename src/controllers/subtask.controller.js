import asyncHandler from "../utils/async-handler.js";

const createSubTask = asyncHandler(async (req, res) => {});

const getSubTasksByTaskId = asyncHandler(async (req, res) => {});

const getSingleSubTask = asyncHandler(async (req, res) => {});

const updateSubTask = asyncHandler(async (req, res) => {});

const deleteSubTask = asyncHandler(async (req, res) => {});

const reorderSubTasks = asyncHandler(async (req, res) => {});

const toggleSubTaskCompletion = asyncHandler(async (req, res) => {});

export {
  createSubTask,
  getSubTasksByTaskId,
  getSingleSubTask,
  updateSubTask,
  deleteSubTask,
  reorderSubTasks,
  toggleSubTaskCompletion,
};
