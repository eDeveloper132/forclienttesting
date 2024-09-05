import 'dotenv/config';

// Define and type the environment variables
const { Name, Password } = process.env;

// Validate environment variables are defined
if (!Name || !Password) {
    throw new Error('Missing environment variables for database connection');
}

// Construct the MongoDB URI
const URI = `mongodb+srv://${Name}:${Password}@smscluster.whyae4e.mongodb.net/test?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=true";`;

export { URI };
