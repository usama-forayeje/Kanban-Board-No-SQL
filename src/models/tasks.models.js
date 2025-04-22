import mongoose, { Schema } from "mongoose";
import { AvailableTaskStatuses, TaskStatusEnum } from "../utils/constants.js";

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
  status: {
    type: String,
    enum: AvailableTaskStatuses,
    default: TaskStatusEnum.TODO,
    required: true,
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
