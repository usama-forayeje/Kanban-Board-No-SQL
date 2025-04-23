import asyncHandler from "../utils/async-handler.js";

// Admin system
const getAllUsers = asyncHandler(async (req, res) => {});

const getSingleUser = asyncHandler(async (req, res) => {});

const deleteUser = asyncHandler(async (req, res) => {});

const banUser = asyncHandler(async (req, res) => {});

const unBanUser = asyncHandler(async (req, res) => {});

export { getAllUsers, getSingleUser, deleteUser, banUser, unBanUser };
