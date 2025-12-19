Node.js Authentication & Authorization Mastery | JWT, OAuth, 2FA, RBAC

NODE_ENV=development
APP_URL=http://localhost:5001
PORT=5001

MONGO_URI=mongodb+srv://manhhungdvh_db_user:dvhung99@cluster0.zpiq5ia.mongodb.net/

JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=

SMTP_HOST="sandbox.smtp.mailtrap.io"
SMTP_PORT=2525
SMTP_USER=""
SMTP_PASS=""
EMAIL_FROM="example@gmail.com"

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback


npx ts-node scripts/totp-qr.ts "otpauth://totp/NodeAdvancedAuthApp:admin%40gmail.com?secret=GMNAMSIWBJLHW4ZY&period=30&digits=6&algorithm=SHA1&issuer=NodeAdvancedAuthApp"
