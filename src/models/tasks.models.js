import mongoose, { Schema } from "mongoose";
import { AvailableTaskStatuses, TaskStatusEnum } from "../utils/constants.js";
import { AvailableTaskPriorityStatuses, taskPriorityEnum } from "../constants/status.js";

const taskSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  description: {
    type: String,
  },
  project: {
    type: Schema.Types.ObjectId,
    ref: "Project",
    required: [true, "Project is required"],
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  assignedTo: {
    type: Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
  status: {
    type: String,
    enum: AvailableTaskStatuses,
    default: TaskStatusEnum.TODO,
    required: true,
  },
  priority: {
    type: String,
    enum: AvailableTaskPriorityStatuses,
    default: taskPriorityEnum.LOW,
  },
  order: {
    type: Number,
    default: 0,
  },
  attachments: {
    type: [
      {
        url: String,
        mimeType: String,
        size: Number,
      },
    ],
    default: [],
  },
});

export const Task = mongoose.model("Task", taskSchema);
