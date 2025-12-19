import jwt from "jsonwebtoken";

export function createAccessToken(UserId: string, role: "user" | "admin", tokenVersion: number) {
    const payload = {
        sub: UserId,
        role,
        tokenVersion,
    }

    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET as string, {
        expiresIn: "30m",
    });
}

export function createRefreshToken(UserId: string, tokenVersion: number) {
    const payload = {
        sub: UserId,
        tokenVersion,
    }

    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET as string, {
        expiresIn: "7d",
    });
}

export function verifyAccessToken(token: string) {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET as string) as { sub: string; role: "user" | "admin"; tokenVersion: number };
}

export function verifyRefreshToken(token: string) {
    try {
        const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET as string) as { sub: string; tokenVersion: number };
        return payload;
    } catch (error) {
        console.error("Error verifying refresh token:", error);
        return null;
    }
}