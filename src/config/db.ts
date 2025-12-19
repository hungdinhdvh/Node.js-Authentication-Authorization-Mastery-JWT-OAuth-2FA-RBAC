import mongoose from 'mongoose';

export async function connectToDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI!, {
            dbName: process.env.MONGO_DB_NAME || 'auth_db',
        });

        console.log("Mongo connection successful established");
    } catch (error) {
        console.error("MongoDB connection error: ", error);
        process.exit(1);
    }
}