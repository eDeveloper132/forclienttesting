import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import path from 'path';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import { SignModel, TokenModel } from './Schema/Post.js';
import MainRoute from './Routes/Main.js';
import SMSRoute from './Routes/SMS.js';
import connection from './DB/db.js';
import PackageDetails from "./Routes/Package.js";
import sendVerificationEmail from './emailService.js'; // Import the email service

const PORT = process.env.PORT || 3437;
const app = express();
app.use(express.json());
app.use(cors());
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
await connection();

const SessionManager = [];
const OneTime = [];
const ExpiredTokens = [];
const FetchUserDetails = [];
const verificateUser = [];
app.use('/assets', express.static(path.join(__dirname, 'assets')));

function clearOneTimeToken() {
    const maxTimeout = Math.pow(2, 31) - 1;
    const timeoutDuration = Math.min(2.592E+09, maxTimeout); // 30 days or max timeout
    setTimeout(async () => {
        if (OneTime.length > 0) {
            console.log("OneTime token expired");
            OneTime.shift();
            const Token = OneTime[0];
            if (Token) {
                const signin = await TokenModel.findOneAndDelete({ Token });
                console.log('Deleted Token', signin);
            }
        }
    }, timeoutDuration);
}
if (OneTime.length > 0) {
    clearOneTimeToken();
}

app.use((req, res, next) => {
    if (req.path.toLowerCase() === '/verify-email' || 
        req.path.toLowerCase() === '/resend-verification' || 
        req.path.toLowerCase() === '/recoverpass') {
        return next();
    }
    
    if (OneTime[0]) {
        const isValidToken = SessionManager.some(session => session.Token === OneTime[0]);
        if (!isValidToken) {
            console.log("Invalid Token");
            OneTime.shift();
            SessionManager.shift();
            return res.redirect('/signin');
        }
        if (req.path.toLowerCase() === '/signin' || req.path.toLowerCase() === '/signup') {
            return res.redirect('/');
        } else {
            console.log("Success");
            next();
        }
    } else {
        console.log('OneTime Token is not set');
        if (req.path.toLowerCase() === '/signin' || req.path.toLowerCase() === '/signup') {
            next();
        } else {
            return res.redirect('/signin');
        }
    }
    
    if (OneTime.length > 0) {
        clearOneTimeToken();
    }
});

app.get("/signup", (req, res) => {
    res.sendFile(path.resolve(__dirname, "./Views/signup.html"));
});
app.post("/signup", async (req, res) => {
    const { Name, Email, Password, Role, Organization, PhoneNumber } = req.body;
    try {
        if (!Name || !Email || !Password || !Role || !Organization || !PhoneNumber) {
            return res.status(400).send("Error: Missing fields");
        }
        const hashedPassword = await bcrypt.hash(Password, 10);
        const token = uuidv4();
        const hashed = await bcrypt.hash(token, 10);
        const verificationToken = hashed;
        
        const newUser = new SignModel({
            id: uuidv4(),
            Name,
            Email,
            Password: hashedPassword,
            PhoneNumber,
            Role,
            Organization,
            verificationToken: verificationToken,
            verificationTokenExpiry: new Date(Date.now() + 3600000),
            isVerified: false,
        });
        await newUser.save();
        
        await sendVerificationEmail(Email, verificationToken);
        console.log("A verification link has been sent to your email.");
        res.redirect('/');
    } catch (error) {
        console.error("Error during signup:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/signin", (req, res) => {
    res.sendFile(path.resolve(__dirname, "./Views/signin.html"));
});

app.post('/signin', async (req, res) => {
    // (Signin logic here)
});

app.use('/', MainRoute);
app.use('/sms', SMSRoute);
app.use('/buypackage', PackageDetails);
app.use("*", (req, res) => {
    res.status(404).sendFile(path.resolve(__dirname, './Views/page-404.html'));
});

export default app;
