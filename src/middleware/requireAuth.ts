import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";
import { email } from "zod";

async function requireAuth(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    try{

        // Here you can verify the token using your token verification logic
        const payload = verifyAccessToken(token);

        const user = await User.findById(payload.sub);

        if(!user) {
            return  res.status(401).json({ message: "User not found!" });
        }

        if(user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Token has been revoked!" });
        }

        const authReq = req as any;

        authReq.user = {
            id: user._id,
            email: user.email,
            name: user.name,
            role: payload.role,
            isEmailVerified: user.isEmailVerified,
        }

        next();

    }catch(err) {
        return res.status(401).json({ message: "Unauthorized" });
    }
}

export default requireAuth;