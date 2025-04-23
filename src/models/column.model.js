import mongoose, { Schema } from "mongoose";

const columnSchema = new mongoose.Schema(
  {
    projectId: {
      type: Schema.Types.ObjectId,
      ref: "Project",
      required: true,
    },
    title: {
      type: String,
      required: true,
    },
    order: {
      type: Number,
      required: true,
      default: 0,
    },
    color: {
      type: String,
      default: "#ffffff",
    },
    archived: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

export const Column = mongoose.model("Column", columnSchema);
