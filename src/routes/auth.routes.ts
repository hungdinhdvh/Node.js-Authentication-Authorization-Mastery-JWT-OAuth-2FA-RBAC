import { Router } from "express";
import { forgotPasswordHandler, loginHandler, logoutHandler, refreshTokenHandler, registerHandler, resetPasswordHandler, verifyEmailHandler } from "../controlers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/login", loginHandler); 
router.post("/refresh-token", refreshTokenHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler); 
router.post("/reset-password", resetPasswordHandler); 

export default router;