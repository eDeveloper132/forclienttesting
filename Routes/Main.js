import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import { FetchUserDetails } from '../index.js';
import axios from 'axios';
// Resolve file and directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();
const findAndUpdateUserById = async (id, updateData) => {
    try {
        // Find the user by id
        const responseFind = await axios.post('https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/findOne', {
            collection: 'signhandlers', // Replace with your actual collection name
            database: 'test', // Replace with your actual database name
            dataSource: 'SMSCluster', // Replace with your actual data source name
            filter: { _id: { $oid: id } } // Filter to find the user by id
        }, {
            headers: {
                'Content-Type': 'application/json',
                'api-key': process.env.MongoDB_API_KEY // Ensure this is set in your environment variables
            }
        });
        // Check if the user exists
        const user = responseFind.data.document;
        if (!user) {
            return { error: "User not found." };
        }
        // Update the user with the new data
        const responseUpdate = await axios.post('https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/updateOne', {
            collection: 'signhandlers', // Replace with your actual collection name
            database: 'test', // Replace with your actual database name
            dataSource: 'SMSCluster', // Replace with your actual data source name
            filter: { _id: { $oid: id } }, // Filter to find the user by id
            update: {
                $set: updateData // Update with the new data
            }
        }, {
            headers: {
                'Content-Type': 'application/json',
                'api-key': process.env.MongoDB_API_KEY // Ensure this is set in your environment variables
            }
        });
        return responseUpdate.data; // Return the result of the update operation
    }
    catch (error) {
        console.error('Error finding and updating user by id:', error.response ? error.response.data : error.message);
        throw new Error('Failed to find and update user by id.');
    }
};
// Route to serve the HTML page
router.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../Views/index.html'));
});
router.get('/changepass', (req, res) => {
    res.sendFile(path.resolve(__dirname, "../Views/changePass.html"));
});
router.post('/changepass', async (req, res) => {
    const { current_password, new_password, confirm_password } = req.body;
    if (!current_password || !new_password || !confirm_password) {
        return res.status(400).send('All fields are required.');
    }
    // Fetch user details from FetchUserDetails
    const user = FetchUserDetails[0].user; // Modify as needed
    if (!user) {
        return res.status(404).send('User not found.');
    }
    try {
        // Verify current password
        const match = await bcrypt.compare(current_password, user.Password);
        if (!match) {
            return res.status(400).send('Current password is incorrect.');
        }
        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10);
        const updated_data = {
            Password: hashedPassword
        };
        // Update user password
        await findAndUpdateUserById(user._id, updated_data);
        res.send('Password changed successfully.');
    }
    catch (error) {
        console.error('Error changing password:', error);
        res.status(500).send({ error: 'Error changing password: ' + error.message });
    }
});
export default router;
