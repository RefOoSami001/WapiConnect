// scripts/update-points.js
require('dotenv').config({ path: '../.env' }); // Load .env from parent directory
const mongoose = require('mongoose');
const User = require('../models/User');

const MONGODB_URI = process.env.MONGODB_URI;

const updateUserPoints = async () => {
    if (process.argv.length !== 4) {
        console.error('Usage: node scripts/update-points.js raafatsami101@gmail.com 200');
        process.exit(1);
    }

    const userEmail = process.argv[2];
    const newPoints = parseFloat(process.argv[3]);

    if (isNaN(newPoints)) {
        console.error('Error: <newPointsBalance> must be a valid number.');
        process.exit(1);
    }

    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB...');

        const user = await User.findOne({ email: userEmail });

        if (!user) {
            console.error(`Error: User with email '${userEmail}' not found.`);
            await mongoose.disconnect();
            process.exit(1);
        }

        user.pointsBalance = newPoints;
        await user.save();

        console.log(`Successfully updated points for user ${userEmail} to ${user.pointsBalance}`);

        await mongoose.disconnect();
        console.log('Disconnected from MongoDB.');
        process.exit(0);

    } catch (error) {
        console.error('Error connecting to DB or updating user points:', error);
        await mongoose.disconnect();
        process.exit(1);
    }
};

updateUserPoints(); 