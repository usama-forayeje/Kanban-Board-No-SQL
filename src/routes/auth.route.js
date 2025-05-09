import { Router } from "express";
import {
  changePassword,
  forgotPassword,
  refreshToken,
  resetPassword,
  signIn,
  signOut,
  signUp,
  socialLogin,
  twoFactorAuth,
  verifyOTP,
  verifyUser,
} from "../controllers/auth.controller.js";
import {
  socialLoginValidator,
  userForgotPasswordValidator,
  userResetPasswordValidator,
  userSigninValidator,
  userSignupValidator,
  userVerifyValidator,
  validateChangePassword,
} from "../validators/index.js";
import { validate } from "../middlewares/validate.middleware.js";
import { verifyJWT } from "../middlewares/verifyJWT.js";

const router = Router();

router.post("/sign-up", userSignupValidator(), validate, signUp);

router.get("/verify/:emailVerificationToken", userVerifyValidator(), verifyUser);

router.post("/sign-in", userSigninValidator(), validate, signIn);

router.post("/sign-out", signOut);

router.post("/forgot-password", userForgotPasswordValidator(), validate, forgotPassword);

router.post(
  "/reset-password/:forgotPasswordToken",
  userResetPasswordValidator(),
  validate,
  resetPassword
);

router.post("/refresh-token", refreshToken);

router.put("/change-password", verifyJWT, validateChangePassword(), validate, changePassword);

router.post('/two-factor-auth', verifyJWT, twoFactorAuth); 

router.post("/verify-otp", verifyJWT, verifyOTP);

router.post("/social-login", socialLoginValidator(), validate, socialLogin);

export default router;
