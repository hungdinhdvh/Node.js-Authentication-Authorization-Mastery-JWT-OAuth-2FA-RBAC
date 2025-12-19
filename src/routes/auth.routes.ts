import { Router } from "express";
import { forgotPasswordHandler, googleAuthCallbackHandler, googleAuthStartHandler, loginHandler, logoutHandler, refreshTokenHandler, registerHandler, resetPasswordHandler, twoFactorSetupHandler, twoFAVerifyHandler, verifyEmailHandler } from "../controlers/auth/auth.controller";
import requireAuth from "../middleware/requireAuth";

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
router.post('/2fa/setup', requireAuth,twoFactorSetupHandler); 
router.post('/2fa/verify', requireAuth, twoFAVerifyHandler);

export default router;