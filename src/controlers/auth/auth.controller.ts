import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";
import crypto from "crypto";

function getAppUrl() {
    if (process.env.NODE_ENV === "production") {
        return process.env.APP_URL || "http://localhost:5001";
    } else {
        return process.env.APP_URL || "http://localhost:5001";
    }
}
export async function registerHandler(req: Request, res: Response) {
    try{
        const result = registerSchema.safeParse(req.body);

        if(!result.success) {
            return res.status(400).json({
                message: "Invalid request",
                errors: result.error.flatten(),
            })
        }

        const { email, password, name } = result.data;

        const nomalizedEmail = email.toLowerCase().trim();

        const existingUser = await User.findOne({ email: nomalizedEmail });

        if(existingUser) {
            return res.status(409).json({ message: "Email already in use! Please use a different email." });
        }

        const passwordHash = hashPassword(password);

        const newlyCreatedUser = new User({
            email: nomalizedEmail,
            password: await passwordHash,
            name,
            role: 'user',
            isEmailVerified: false, 
            twoFactorEnabled: false,
        });
        
        await newlyCreatedUser.save();

        // email verification part

        const verifyToken = jwt.sign(
            {
                sub: newlyCreatedUser._id,
            },
            process.env.JWT_ACCESS_SECRET as string,
            {
                expiresIn: "1d",
            }
        );

        const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

        await sendEmail(
            newlyCreatedUser.email,
            "Verify your email address",
            `<p>Click the link below to verify your email address:</p>
            <a href="${verifyUrl}">${verifyUrl}</a>
            <p>This link will expire in 1 day.</p>
            `
        );

        return res.status(201).json({
            message: "User registered successfully. Please check your email to verify your account.",
            user: {
                id: newlyCreatedUser._id,
                email: newlyCreatedUser.email,
                name: newlyCreatedUser.name,
                role: newlyCreatedUser.role,
                isEmailVerified: newlyCreatedUser.isEmailVerified,
            }
        });

    }catch(error) {
        console.error("Error in registerHandler:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export async function verifyEmailHandler(req: Request, res: Response) {
    const token = req.query.token as string | undefined;

    if(!token) {
        return  res.status(400).json({ message: "Verification token is missing" });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET as string) as { sub: string };

        const user = await User.findById(payload.sub);
        if(!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if(user.isEmailVerified) {
            return res.status(400).json({ message: "Email is already verified" });
        }

        user.isEmailVerified = true;
        await user.save();

        return res.status(200).json({ message: "Email verified successfully! You can now login." });
    }catch (error) {
        console.error("Error in verifyEmailHandler:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export async function loginHandler(req: Request, res: Response) {
   try {
     const result = loginSchema.safeParse(req.body);

        if(!result.success) {
            return res.status(400).json({
                message: "Invalid request",
                errors: result.error.flatten(),
            })
        }

        const { email, password } = result.data;

        const nomalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({ email: nomalizedEmail });

        if(!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const isPasswordValid = await checkPassword(password, user.password);

        if(!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password" });
        }

        if(!user.isEmailVerified) {
            return res.status(403).json({ message: "Email is not verified. Please verify your email before logging in." });
        }

        const accessToken = createAccessToken(user._id.toString(), user.role as "user" | "admin", user.tokenVersion);
        const refreshToken = createRefreshToken(user._id.toString(), user.tokenVersion);

        const isProd = process.env.NODE_ENV === "production";

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days      
            });

        return res.status(200).json({
            message: "Login successful",
            accessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });

   }catch (error) {
       console.error("Error in loginHandler:", error);
       res.status(500).json({ message: "Internal server error" });
   }
}

export async function refreshTokenHandler(req: Request, res: Response)  {
    try {
        const token = req.cookies.refreshToken as string | undefined;

        if(!token) {
            return res.status(401).json({ message: "Refresh token is missing" });
        }
        
        const payload = verifyRefreshToken(token);

        const user = await User.findById(payload?.sub);

        if(!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if(user.tokenVersion !== payload?.tokenVersion) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const newAccessToken = createAccessToken(user._id.toString(), user.role as "user" | "admin", user.tokenVersion);
        const newRefreshToken = createRefreshToken(user._id.toString(), user.tokenVersion);

        const isProd = process.env.NODE_ENV === "production";

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days      
            });

        return res.status(200).json({
            message: "Token refreshed successfully",
            accessToken: newAccessToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });
    }catch (error) {
        console.error("Error in refreshTokenHandler:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export async function logoutHandler(req: Request, res: Response) {
    res.clearCookie("refreshToken", { path: "/" });
 
    return res.status(200).json({ message: "Logged out successfully" });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
    const { email } = req.body;

    if(!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    const nomalizedEmail = email.toLowerCase().trim();

    try {

        const user = await User.findOne({ email: nomalizedEmail });

        if(!user) {
            return res.status(404).json({ message: "If an account with that email exists, a password reset link has been sent." });
        }

        const rawToken = crypto.randomBytes(32).toString("hex");

        const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

        user.resetPasswordToken = tokenHash;
        user.resetPasswordTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now

        await user.save();

        const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}&email=${encodeURIComponent(user.email)}`;

        await sendEmail(
            user.email,
            "Password Reset Request",
            `<p>Click the link below to reset your password:</p>
            <a href="${resetUrl}">${resetUrl}</a>
            <p>This link will expire in 15 minutes.</p>
            `
        );

        return res.status(200).json({ message: "If an account with that email exists, a password reset link has been sent." });

    }catch (error) {
        console.error("Error in forgotPasswordHandler:", error);
        res.status(500).json({ message: "Internal server error" });
    }

}

export async function resetPasswordHandler(req: Request, res: Response) {
    const { token, email, password } = req.body as { token?: string; email?: string; password?: string };

    if(!token || !email || !password) {
        return res.status(400).json({ message: "Token, email, and new password are required" });
    }

    const nomalizedEmail = email.toLowerCase().trim();

    try {
        const user = await User.findOne({ email: nomalizedEmail });

        if(!user || !user.resetPasswordToken || !user.resetPasswordTokenExpires) {
            return res.status(400).json({ message: "Invalid or expired password reset token" });
        }

        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

        if(tokenHash !== user.resetPasswordToken || user.resetPasswordTokenExpires < new Date()) {
            return res.status(400).json({ message: "Invalid or expired password reset token" });
        }

        user.password = await hashPassword(password);
        user.resetPasswordToken = undefined;
        user.resetPasswordTokenExpires = undefined;

        await user.save();

        return res.status(200).json({ message: "Password has been reset successfully. You can now login with your new password." });

    }catch (error) {
        console.error("Error in resetPasswordHandler:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}