// emailConfig.js
import nodemailer from 'nodemailer';
import 'dotenv/config'; // Ensure this line is at the top if not already included in your main file
// Create a transporter object using SMTP transport
const transporter = nodemailer.createTransport({
    service: 'Gmail', // You can use any email service provider
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
export default transporter;
