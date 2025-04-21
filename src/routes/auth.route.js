import { Router } from "express";
import { singUp } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userSignupValidator } from "../validators/index.js";

const router = Router();

router.get("/", userSignupValidator(),validate, singUp)

export default router;
