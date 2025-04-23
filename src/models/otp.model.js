import mongoose, { Schema } from "mongoose";

const OtpSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    otp: {
      type: Number,
      required: true,
    },
    isUsed: {
      type: Boolean,
      default: false,
    },
    purpose: {
      type: String,
      enum: ["register", "login", "reset-password", "verify-email", "verify-phone"],
    },
    expiredAt: {
      type: Date,
      required: true,
    },
  },
  { timestamps: true }
);

export const Otp = mongoose.model("Otp", OtpSchema);
