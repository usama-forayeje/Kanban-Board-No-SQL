import { Router } from "express";


const router = Router();

router.get("/",validate, singUp)

export default router;
