import { Router } from "express";
import { forgotPasswordHandler, googleAuthCallbackHandler, googleAuthStartHandler, loginHandler, logoutHandler, refreshTokenHandler, registerHandler, resetPasswordHandler, verifyEmailHandler } from "../controlers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/login", loginHandler); 
router.post("/refresh-token", refreshTokenHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler); 
router.post("/reset-password", resetPasswordHandler); 
router.get('/google', googleAuthStartHandler);
router.get('/google/callback', googleAuthCallbackHandler);

export default router;