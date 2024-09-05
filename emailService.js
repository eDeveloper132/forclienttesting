// emailService.js
import transporter from './emailconfig.js';
import { URL } from 'url';
async function sendVerificationEmail(Email, verificationToken) {
    if (!Email) {
        console.error("No recipient email defined");
        return;
    }
    const verificationURL = new URL(`https://39db-223-123-111-156.ngrok-free.app/verify-email`);
    verificationURL.searchParams.append('token', verificationToken);
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: Email, // Ensure this is correctly defined
        subject: 'Verify Your Email',
        text: `Please verify your email for using SMS PORTAL by clicking on the following link: ${verificationURL}`,
        html: `
            <p>Please verify your email for using SMS PORTAL by clicking on the following link:</p>
            <p><a href="${verificationURL}">Verify Email</a></p>
        `
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log("Verification email sent successfully");
    }
    catch (error) {
        console.error("Failed to send verification email:", error);
    }
}
export default sendVerificationEmail;
