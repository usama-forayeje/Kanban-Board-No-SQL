import mongoose, { Schema } from "mongoose";

const loginLogSchema = new mongoose.Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    ipAddress: {
      type: String,
      required: true,
    },
    deviceInfo: {
      type: String,
      required: true,
    },
    loggedInAt: {
      type: Date,
      default: Date.now,
    },
    loggedOutAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

export const LoginLog = mongoose.model("LoginLog", loginLogSchema);
