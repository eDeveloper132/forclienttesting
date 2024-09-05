import mongoose, { ConnectOptions } from 'mongoose';
import { URI } from '../Utils/Config.js';

const connection = (): mongoose.Connection => {
    // Connection options
    const options: ConnectOptions = {
        serverSelectionTimeoutMS: 5000, // Adjust as needed
        socketTimeoutMS: 45000,         // Adjust as needed
        maxPoolSize: 10,                // Adjust as needed
        // TLS/SSL options if needed
        tls: true, // Use TLS/SSL
        tlsAllowInvalidCertificates: false, // Only if you want to allow self-signed certificates
    };

    // Function to connect with retry logic
    const connectWithRetry = (): void => {
        mongoose.connect(URI, options)
            .then(() => {
                console.log('Mongoose is connected');
            })
            .catch(err => {
                console.error('Mongoose connection error: ', err);
                // Retry connection after a delay
                setTimeout(connectWithRetry, 5000); // Retry after 5 seconds
            });
    };

    // Initial connection attempt
    connectWithRetry();

    // Event listeners for connection
    mongoose.connection.on('disconnected', () => {
        console.log('Mongoose is disconnected');
        // Reconnect if disconnected
        connectWithRetry();
    });

    mongoose.connection.on('error', (err: Error) => {
        console.error('Mongoose connection error: ', err);
        // Retry connection on error
        connectWithRetry();
    });

    // Handle application termination
    process.on('SIGINT', () => {
        console.log('app is terminating');
        mongoose.connection.close(); // No callback provided
        console.log('Mongoose default connection closed');
        process.exit(0);
    });
    

    return mongoose.connection;
};

export default connection;
