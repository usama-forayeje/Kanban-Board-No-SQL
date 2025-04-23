import asyncHandler from "../utils/async-handler.js";

const addTaskWatcher = asyncHandler(async (req, res) => {});

const removeWatcher = asyncHandler(async (req, res) => {});

const getWatchersByTask = asyncHandler(async (req, res) => {});

const getWatchedTasksByUser = asyncHandler(async (req, res) => {});

export { addTaskWatcher, removeWatcher, getWatchersByTask, getWatchedTasksByUser };
