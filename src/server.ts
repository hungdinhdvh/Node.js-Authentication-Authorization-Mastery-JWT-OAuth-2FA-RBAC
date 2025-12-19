import { connectToDB } from "./config/db";
import dotenv from 'dotenv';
import http from 'http';
import app from "./app";

dotenv.config();


async function startServer() {
    await connectToDB();

    const server = http.createServer(app);

    server.listen(process.env.PORT, () => {
        console.log(`Server is running on port ${process.env.PORT}`);
    })
}

startServer().catch((error) => {
    console.error("Error while starting the server:", error);
    process.exit(1);
});