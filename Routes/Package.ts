import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import axios from 'axios';
import Stripe from 'stripe';
import { FetchUserDetails } from '../index.js';
import { SignModel, ISign } from '../Schema/Post.js';

// Initialize Stripe with the secret key from environment variables
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string, { apiVersion: '2024-06-20' });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// Route to serve the HTML page
router.get('/', (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, '../Views/buypackage.html'));
});

// Route to get packages from the API
router.get('/api/getpackages', async (req: Request, res: Response) => {
    const data = JSON.stringify({
        collection: 'packagehandlers',
        database: 'test',
        dataSource: 'SMSCluster',
        projection: {
            _id: 1,
            id: 1,
            Name: 1,
            Amount: 1,
            Duration: 1,
            Coins: 1,
            Description: 1
        }
    });

    const config = {
        method: 'post',
        url: 'https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/find',
        headers: {
            'Content-Type': 'application/json',
            'api-key': process.env.MongoDB_API_KEY as string,
        },
        data: data
    };

    try {
        const response = await axios(config);
        res.json(response.data);
    } catch (error: any) {
        console.error("Error fetching data:", error);
        res.status(500).send("Error fetching data");
    }
});

// Placeholder for package details
let oic: [string, string, string, number, number, number, string];

// Route to handle successful payment
router.get('/succeed', (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, '../Views/success.html'));
});

router.post('/succeed', async (req: Request, res: Response) => {
    try {
        const packageDurationInDays: number = oic[4]; // e.g., 30
        const currentDate: Date = new Date();

        // Calculate the new expiry date by adding the package duration to the current date
        const newPackageExpiry: Date = new Date(currentDate);
        newPackageExpiry.setDate(currentDate.getDate() + packageDurationInDays);

        console.log(`New package expiry date: ${newPackageExpiry.toDateString()}`);

        // Function to find the package by name
        const findPkgByName = async (Pkg: string) => {
            try {
                const response = await axios.post(
                    'https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/findOne',
                    {
                        collection: 'packagehandlers',
                        database: 'test',
                        dataSource: 'SMSCluster',
                        filter: { Name: Pkg }
                    },
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            'api-key': process.env.MongoDB_API_KEY as string
                        }
                    }
                );

                return response.data.document || null;
            } catch (error: any) {
                console.error('Error finding package:', error.response ? error.response.data : error.message);
                throw new Error('Failed to check if the package exists.');
            }
        };

        // Find the package by name
        const finded = await findPkgByName(oic[2]);
        console.log(finded);
        const userData = FetchUserDetails[0]; // Fetch user details from your method
        const userId = userData.user._id;
        // Update user details with package information
        const updatedUser = await SignModel.findByIdAndUpdate(
            userId,
            {
                $set: {
                    "Details.Coins": oic[5],
                    "Details.PackageName": oic[2],
                    "Details.PackageExpiry": newPackageExpiry,
                    "package": finded?._id
                }
            },
            { new: true, runValidators: true }
        );

        if (updatedUser) {
            await updatedUser.save();
            console.log("User details updated successfully:", updatedUser);
        } else {
            console.error("User not found.");
        }

        // Clear the session data
        oic = ["", "", "", 0, 0, 0, ""];

        // Assuming you have a session reset endpoint in your Express app
        // await axios.post('/reset-Session');

        res.send(200);
    } catch (error: any) {
        console.error('Error in payment success handling:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle package purchase
router.post('/buy', async (req: Request, res: Response) => {
    const { currentPackageDetails } = req.body;

    if (!currentPackageDetails || !currentPackageDetails.id) {
        return res.status(400).send('Invalid package details');
    }
    const findPkgByName = async (Pkg: string) => {
      try {
          const response = await axios.post(
              'https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/findOne',
              {
                  collection: 'packagehandlers',
                  database: 'test',
                  dataSource: 'SMSCluster',
                  filter: { Name: Pkg }
              },
              {
                  headers: {
                      'Content-Type': 'application/json',
                      'api-key': process.env.MongoDB_API_KEY as string
                  }
              }
          );

          return response.data.document || null;
      } catch (error: any) {
          console.error('Error finding package:', error.response ? error.response.data : error.message);
          throw new Error('Failed to check if the package exists.');
      }
  };
  const finded = await findPkgByName(currentPackageDetails.name)
    oic = [
        currentPackageDetails._id,
        currentPackageDetails.id,
        currentPackageDetails.name,
        currentPackageDetails.amount,
        currentPackageDetails.duration,
        currentPackageDetails.coins,
        currentPackageDetails.description
    ];

    const userData = FetchUserDetails[0]; // Fetch user details from your method
    const userId = userData.user._id;

    try {
        // Check if the user already has an active package
        const user = await SignModel.findById(userId);
        if (user?.Details?.PackageExpiry instanceof Date) {
            user.Details.PackageExpiry = currentPackageDetails.duration;
            await user.save();
            console.log('****************************************', user ,'************************************');
        }

        const user_s = await SignModel.findById(userId);

        if (!user_s) {
            return res.status(404).send('User not found');
        }

        if (!user_s.Details) {
            return res.status(400).send('User details not found');
        }

        const currentPackage = currentPackageDetails.name;
        const packageExpiry = user_s.Details.PackageExpiry; // Assuming you store expiry date/time

        if (currentPackage && packageExpiry) {
            const now = new Date();

            // Check if the current package has expired
            if (new Date(packageExpiry) > now) {
                return res.status(400).send(`You already have an active package (${currentPackage}) that expires on ${packageExpiry}.`);
            }
        }

        const amountInDollars = currentPackageDetails.amount;
        if (isNaN(amountInDollars) || amountInDollars <= 0) {
            return res.status(400).send('Invalid amount');
        }

        console.log("AMOUNT", amountInDollars);

        let paymentMethod = "stripe";
        if (paymentMethod === 'stripe') {
            const paymentLink = await stripe.paymentLinks.create({
                line_items: [
                    {
                        price: `${finded.price_id}`,
                        quantity: 1,
                    },
                ],
                after_completion: {
                    type: 'redirect',
                    redirect: {
                        url: 'https://39db-223-123-111-156.ngrok-free.app/buypackage/succeed',
                    },
                },
            });

            console.log('Stripe payment successful:', paymentLink);
            return res.status(200).send({ link: paymentLink.url });
        } else {
            return res.status(400).send('Unsupported payment method');
        }

    } catch (error: any) {
        console.error('Error processing payment:', error);
        res.status(500).json({ message: 'Payment processing failed.', error: error.message });
    }
});

// Route to show brought package page
router.get('/broughtpackage', (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, '../Views/BroughtPackage.html'));
});

// Route to fetch user package
router.get('/api/package', async (req: Request, res: Response) => {
    try {
        const useri = FetchUserDetails[0]?.user;
        const userId = useri._id;

        if (!userId) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const user = await SignModel.findById(userId).populate('package').exec() as ISign;

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const findUserById = async (id: any) => {
            try {
                const response = await axios.post(
                    'https://ap-southeast-1.aws.data.mongodb-api.com/app/data-mdipydh/endpoint/data/v1/action/findOne',
                    {
                        collection: 'packagehandlers',
                        database: 'test',
                        dataSource: 'SMSCluster',
                        filter: { _id: { $oid: id } }
                    },
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            'api-key': process.env.MongoDB_API_KEY as string
                        }
                    }
                );

                return response.data.document || null;
            } catch (error: any) {
                console.error('Error finding user by id:', error.response ? error.response.data : error.message);
                throw new Error('Failed to find user by id.');
            }
        };

        if (user.package) {
            const packageData = await findUserById(user.package);
            res.status(200).json({ message: 'Package found', package: packageData });
        } else {
            res.status(404).json({ message: 'Package not found' });
        }

    } catch (error: any) {
        console.error('Error fetching user package:', error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

export default router;
