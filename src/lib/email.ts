import nodemailer from "nodemailer";
import fa from "zod/v4/locales/fa.js";

export async function sendEmail(to: string, subject: string, html: string) {
    if(!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
        throw new Error("SMTP configuration is missing in environment variables"); 
    }

    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || 587);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const from = process.env.EMAIL_FROM;

    const transporter = nodemailer.createTransport({
        host,
        port,
        secure: false, 
        auth: {
            user,
            pass,
        },
    });

    await transporter.sendMail({
        from, to, subject, html
    });


}