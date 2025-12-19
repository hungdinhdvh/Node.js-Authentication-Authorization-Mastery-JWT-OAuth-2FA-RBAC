import e, { NextFunction, Request, Response } from "express";

function requireRole(role: 'user' | 'admin') {
    return (req: Request, res: Response, next: NextFunction) => {
        const authReq = req as any;
        const authUser = authReq.user;
        
        if (!authUser) {
            return res.status(401).json({ message: "You must be logged in to access this resource." });
        }   

        if (authUser.role !== role) {
            return res.status(403).json({ message: "You do not have the required role to access this resource." });
        }

        next();
    }
}

export default requireRole;