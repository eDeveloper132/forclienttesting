import express from 'express';
import 'dotenv/config';
import { fileURLToPath } from 'url';
import path from 'path';
import axios from 'axios';
import { MessageModel } from '../Schema/Post.js';
import { v4 as uuidv4 } from 'uuid';
import { FetchUserDetails } from '../index.js';
import { SignModel } from '../Schema/Post.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();
// Route to serve the HTML file
router.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../Views/sms.html'));
});
// POST route to handle SMS sending
router.post('/', async (req, res) => {
    const { phonecode, phonenumber, message } = req.body;
    if (!phonecode || !phonenumber || !message) {
        console.log('Server Error 400: Missing required fields');
        return res.status(400).json({ error: 'Please fill in all the required fields: phone code, phone number, and message.' });
    }
    const user = FetchUserDetails[0]?.user;
    const packageName = user?.Details?.PackageName;
    const coins = user?.Details?.Coins;
    if (!packageName || !coins) {
        console.log('Server Error 403: User package details are incomplete.');
        return res.status(403).json({ error: 'You cannot send SMS. Please buy our package first.' });
    }
    const mix = `${phonecode}${phonenumber}`;
    console.log(`We are delivering this message: ${message} to ${mix}`);
    try {
        // Send SMS using ClickSend API
        const smsMessage = {
            to: mix,
            body: message
        };
        const apiUrl = 'https://rest.clicksend.com/v3/sms/send';
        const response = await axios.post(apiUrl, {
            messages: [smsMessage]
        }, {
            auth: {
                username: "bluebirdintegrated@gmail.com",
                password: "EA26A5D0-7AAC-6631-478B-FC155CE94C99"
            }
        });
        console.log(response.data);
        const userData = FetchUserDetails[0];
        const userId = userData.user._id;
        const dbUser = await SignModel.findById(userId);
        if (!dbUser) {
            return res.status(404).send('User not found');
        }
        if (!dbUser.Details) {
            return res.status(400).send('User details not found');
        }
        // Deduct one coin from the user's balance
        let coins = dbUser.Details.Coins;
        if (typeof coins === "number") {
            coins -= 1;
            if (coins <= 0) {
                return res.status(400).send('Insufficient coins for sending message');
            }
            dbUser.Details.Coins = coins;
        }
        // Create a new message entry in the database
        const newMessage = await MessageModel.create({
            id: uuidv4(),
            u_id: dbUser._id,
            from: 'NOT PROVIDED',
            to: mix,
            message: message,
            m_count: response.data.data.total_count,
            m_schedule: 'NOT PROVIDED',
            status: response.data.response_code
        });
        // Cast newMessage._id to ObjectId
        const messageId = newMessage._id;
        // Add the message to the user's messages array and save the user
        dbUser.messages.push(messageId);
        await dbUser.save();
        console.log('Data Updated Successfully', dbUser);
        console.log('Data Added Successfully', newMessage);
        // Respond with success
        res.status(200).json({ message: 'Message sent successfully!' });
    }
    catch (err) {
        console.error(err.response ? err.response.data : err.message);
        res.status(500).json({ error: 'Failed to send SMS. Please try again later.' });
    }
});
router.get('/messages', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../Views/messageslist.html'));
});
// API endpoint to fetch messages
router.get('/api/messages', async (req, res) => {
    try {
        const useri = FetchUserDetails[0]?.user;
        const userId = useri._id;
        if (!userId) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        // Find the user by their ID and populate the messages field
        const user = await SignModel.findById(userId).populate('messages').exec();
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Send the user's messages as a response
        res.status(200).json({ messages: user.messages });
    }
    catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
export default router;
