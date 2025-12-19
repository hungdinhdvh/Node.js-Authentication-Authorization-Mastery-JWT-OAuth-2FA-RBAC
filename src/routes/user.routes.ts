import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";

const router = Router();

router.get("/profile", requireAuth, (req: Request, res: Response) => {
    const authReq = req as any;

    const authUser = authReq.user;

    res.json({ user: authUser });
});

export default router;