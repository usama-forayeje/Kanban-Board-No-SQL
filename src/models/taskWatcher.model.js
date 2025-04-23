import mongoose, { Schema } from "mongoose";

const taskWatcherSchema = new Schema(
  {
    taskId: {
      type: Schema.Types.ObjectId,
      ref: "Task",
      required: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    addedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: false }
);

export const TaskWatcher = mongoose.model("TaskWatcher", taskWatcherSchema);
