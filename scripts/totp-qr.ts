import QRCode from 'qrcode';

const otpAuthUrl = process.argv[2];

if(!otpAuthUrl) {
    throw new Error("Pass optAuthUrl as argument");
}

async function main() {
    await QRCode.toFile('totp-qr.png', otpAuthUrl);
    console.log("QR code saved to totp-qr.png");
}

main().catch(err => {
    console.error("Error generating QR code:", err);
    process.exit(1);
});