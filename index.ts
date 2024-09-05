import express, { Request, Response, NextFunction } from 'express';
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

const SessionManager: Array<{ Token: string }> = [];
const OneTime: string[] = [];
const ExpiredTokens: Array<{ Token: string }> = [];
const FetchUserDetails: Array<{ user: any }> = []; // Adjust the type based on your actual user schema
const verificateUser: any[] = [];

app.use('/assets', express.static(path.join(__dirname, 'assets')));

function clearOneTimeToken() {
    const maxTimeout = Math.pow(2, 31) - 1; // Maximum timeout value in JavaScript
    const timeoutDuration = Math.min(2.592E+09, maxTimeout); // 30 days or max timeout

    setTimeout(async () => {
        if (OneTime.length > 0) {
            console.log("OneTime token expired");
            OneTime.shift();
            const Token = OneTime[0];
            if (Token) {
                const signin = await TokenModel.findOneAndDelete({ Token });
                console.log('Deleted Token', signin);
                // Additional logic can be added here, like notifying the user
            }
        }
    }, timeoutDuration);
}

// Initially set the timeout to clear the token if already present
if (OneTime.length > 0) {
    clearOneTimeToken();
}

app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.toLowerCase() === '/verify-email') {
        return next();
    } else if (req.path.toLowerCase() === '/resend-verification') {
        return next();
    } else if (req.path.toLowerCase() === '/recoverpass') {
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

    // Reset the timeout whenever a new token is set in OneTime array
    if (OneTime.length > 0) {
        clearOneTimeToken();
    }
});

app.get("/signup", (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, "./Views/signup.html"));
});

app.post("/signup", async (req: Request, res: Response) => {
    const { Name, Email, Password, Role, Organization, PhoneNumber } = req.body;

    try {
        // Validate required fields
        if (!Name || !Email || !Password || !Role || !Organization || !PhoneNumber) {
            return res.status(400).send("Error: Missing fields");
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(Password, 10);

        const token = uuidv4(); // Use UUID or any unique token generator
        const hashed = await bcrypt.hash(token, 10)
        const verificationToken = hashed;

        // Create the new user
        const newUser = new SignModel({
            id: uuidv4(),
            Name,
            Email,
            Password: hashedPassword,
            PhoneNumber,
            Role,
            Organization,
            verificationToken: verificationToken,
            verificationTokenExpiry: new Date(Date.now() + 3600000) ,
            isVerified: false, // User is not verified initially
        });

        await newUser.save();


        // Send verification email
        await sendVerificationEmail(Email, verificationToken);

        console.log("A verification link has been sent to your email. Please check your inbox or spam folder.");
        res.redirect('/');
    } catch (error: any) {
        console.error("Error during signup:", error);
        res.status(500).send("Internal Server Error");
    }
});
app.get("/signin", (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, "./Views/signin.html"));
});

app.post('/signin', async (req: Request, res: Response) => {
    const { Email, Password } = req.body;

    try {
        if (!Email || !Password) {
            return res.status(400).send('Error: Missing fields');
        }

        const user = await SignModel.findOne({ Email });
        if (!user || !user.Password) {
            console.log('User or Password not found');
            return res.status(401).send('Error: Invalid email or password');
        }

        // Ensure Password and user.Password are strings before comparing
        const isMatch = await bcrypt.compare(Password, user.Password);
        if (!isMatch) {
            console.log('Password does not match');
            return res.status(401).send('Error: Invalid password');
        }

        if (user.Role === "Admin") {
            return res.status(401).send('Error: You are not a User');
        }

        if (user.isVerified) {
            const token = uuidv4();
            const hashedToken = await bcrypt.hash(token, 10);
            await SessionManager.push({
                Token: hashedToken
            });
            const signin = await TokenModel.create({
                Token: hashedToken
            });
            await signin.save();
            await OneTime.push(hashedToken);
            await ExpiredTokens.push({
                Token: hashedToken
            });
            await FetchUserDetails.push({
                user
            });
            console.log('User logged in:', user);
            console.log('Uploaded Id on Database:', signin);
            console.log('Generated access token:', hashedToken);
            res.redirect('/');
        } else {
            res.redirect('/signup');
        }
    } catch (error: any) {
        console.error('Error during login:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/reset-Session', async (req: Request, res: Response) => {
    const Token = OneTime[0];
    if (Token) {
        const signin = await TokenModel.findOneAndDelete({ Token });
        console.log('Deleted Token', signin);
        OneTime.shift();
        SessionManager.shift();
        FetchUserDetails.shift();
    }
    res.status(200).send("Session reset");
});

app.post('/user', async (req: Request, res: Response) => {
    const Data = FetchUserDetails[0];
    console.log(Data);

    try {
        if (!Data || !Data.user || !Data.user.Email || !Data.user.Password) {
            return res.status(400).send('Error: Missing fields');
        }

        const Id = Data.user._id;
        const user = await SignModel.findById(Id);
        if (!user) {
            console.log('User not found');
            return res.status(401).send('Error: Invalid email');
        }

        const data = {
            Name: user.Name,
            Email: user.Email,
            Password: user.Password,
            PackageName: user.Details?.PackageName,
            Coins: user.Details?.Coins
        };

        res.send(data);
    } catch (error: any) {
        console.error('Error during user data fetch:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.use('/', MainRoute);
app.use('/sms', SMSRoute);
app.use('/buypackage', PackageDetails);
const arrey: string[] =[];
app.post('/recoverpass', async (req: Request, res: Response ) => {
    const { email } = req.body;

    try {
        const user = await SignModel.findOne({ Email: email });

        if (!user) {
            console.log('User not found');
            return res.status(401).send('Invalid email address. Please try again.');
        }
        const Id = user._id;
function generateTemporaryPassword(length: number = 10): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';

    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        password += characters[randomIndex];
    }

    return password;
}

// Example usage
const temporaryPassword = generateTemporaryPassword(12);
        const hashedPassword = await bcrypt.hash(temporaryPassword, 10);
        arrey.push(hashedPassword);

        const FORVERIFICATION = arrey[0];
        const updatedUser = await SignModel.findByIdAndUpdate(
            Id,
            {
                $set: { 
                    "Password": arrey[0],
                    "verificationToken": FORVERIFICATION,
                    "verificationTokenExpiry": new Date(Date.now() + 3600000),
                    "isVerified": false 
                }
            },
            { new: true, runValidators: true }
        );
        updatedUser?.save();

        await sendVerificationEmail(email, FORVERIFICATION);

        if (!updatedUser) {
            return res.status(500).send('Failed to update the password. Please try again.');
        }

        console.log(`Temporary password for ${email}: ${hashedPassword}`);
        res.send({
            message: `A verification link has been sent to your email. Please copy and save the temporary password provided password: ${temporaryPassword}.`,
        });
    } catch (error: any) {
        console.error('Error in /recoverpass:', error);
        res.status(500).send('An internal server error occurred. Please try again later.');
    }
});

app.get('/verify-email', async (req: Request, res: Response) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send('Verification token is required.');
    }

    try {
        // Find the user with the matching verification token and check if it's still valid
        const user = await SignModel.findOne({
            verificationToken: token,
            verificationTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired token.');
        }

        // Mark the user as verified
        user.isVerified = true;
 // Clear the token expiry
        await user.save();
        // const redirectToken = uuidv4();
        // const hash = await bcrypt.hash(redirectToken , 10);
        // OneTime.push(hash)
        // res.redirect('/');
        res.send('Email verified successfully!');
    } catch (error: any) {
        console.error("Error verifying email:", error);
        res.status(500).send('Server error');
    }
});

app.post('/resend-verification', async (req, res) => {
    const { Email } = req.body;

    try {
        const user = await SignModel.findOne({ Email });
        if (!user) {
            return res.status(404).send('Error: User not found');
        }

        if (user.isVerified) {
            return res.status(400).send('Error: Email is already verified');
        }

        const token = uuidv4(); // Use UUID or any unique token generator
        const hashed = await bcrypt.hash(token, 10)
        const verificationToken = hashed;

        user.verificationToken = hashed,
        user.verificationTokenExpiry = new Date(Date.now() + 3600000);

        user.save();
        await sendVerificationEmail(Email, verificationToken);

        res.status(200).send('Verification email sent');
    } catch (error: any) {
        console.error('Error resending verification email:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.use("*", (req: Request, res: Response) => {
    res.status(404).sendFile(path.resolve(__dirname, './Views/page-404.html'));
});

export {
    FetchUserDetails,
    OneTime,
    SessionManager
};
