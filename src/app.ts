import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import adminRoutes from './routes/admin.routes';

const app = express();

app.use(express.json());

app.use(cookieParser());

app.get('/health', (req, res) => {
    res.json({ status: 'OK' });
});

app.use("/auth", authRoutes);

app.use("/user", userRoutes);

app.use("/admin", adminRoutes);

export default app;