import { body, param } from "express-validator";

const userSignupValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is not valid"),

    body("userName")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ];
};

const userVerifyValidator = () => {
  return [
    param("emailVerificationToken")
      .trim()
      .notEmpty()
      .withMessage("🔐 Verification token is required"),
  ];
};

const userSigninValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("📧 Email is required")
      .isEmail()
      .withMessage("❌ Invalid email address format")
      .normalizeEmail(),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("🔑 Password is required")
      .isLength({ min: 6 })
      .withMessage("❗Password must be at least 6 characters long"),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("📧 Email is required")
      .isEmail()
      .withMessage("❌ Invalid email address format")
      .normalizeEmail(),
  ];
};

const userResetPasswordValidator = () => {
  return [
    param("forgotPasswordToken")
      .trim()
      .notEmpty()
      .withMessage("🔐 Reset forgotPasswordToken is required"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("🔑 New password is required")
      .isLength({ min: 6 })
      .withMessage("❗New password must be at least 6 characters long"),
  ];
};

const validateChangePassword = () => {
  return [
    body("oldPassword").notEmpty().withMessage("🗝️ Old Password is required"),

    body("newPassword")
      .notEmpty()
      .withMessage("⚠️ New Password is required")
      .isLength({ min: 6 })
      .withMessage("❗New password must be at least 6 characters long"),

    body("confirmPassword")
      .notEmpty()
      .withMessage("⚠️ confirm Password is required")
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error("❌ Passwords do not match");
        }
        return true;
      }),
  ];
};

const socialLoginValidator = () => {
  return [
    body("email").isEmail().withMessage("A valid email is required"),


    body("provider")
      .notEmpty()
      .isIn(["google", "facebook", "github"])
      .withMessage("Provider must be google, facebook or github"),

    body("profileImage").optional().isURL().withMessage("Profile image must be a valid URL"),
  ];
};

export {
  userSignupValidator,
  userSigninValidator,
  userVerifyValidator,
  userForgotPasswordValidator,
  userResetPasswordValidator,
  validateChangePassword,
  socialLoginValidator,
};
