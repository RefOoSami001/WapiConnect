// scripts/update-points.js
require('dotenv').config({ path: '../.env' }); // Load .env from parent directory
const mongoose = require('mongoose');
const User = require('../models/User');
const Session = require('../models/Session');

const MONGODB_URI = process.env.MONGODB_URI;

const updateUserPoints = async () => {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB...');

        // If no arguments provided, display all users with their points
        if (process.argv.length === 2) {
            const users = await User.find({}).sort({ pointsBalance: -1 });
            console.log('\nDetailed User Information:');
            console.log('='.repeat(100));

            for (const user of users) {
                // Get active sessions for the user
                const activeSessions = await Session.find({
                    userId: user._id,
                    status: 'connected'
                });

                // Format last login date
                const lastLogin = user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never';

                // Format creation date
                const createdAt = user.createdAt ? new Date(user.createdAt).toLocaleString() : 'Unknown';

                console.log(`\nUser: ${user.name} (${user.email})`);
                console.log('-'.repeat(50));
                console.log(`Points Balance: ${user.pointsBalance}`);
                console.log(`Profile Picture: ${user.profilePictureUrl || 'Not set'}`);
                console.log(`Created At: ${createdAt}`);
                console.log(`Last Login: ${lastLogin}`);
                console.log(`Active Sessions: ${activeSessions.length}`);

                if (activeSessions.length > 0) {
                    console.log('\nActive Session Details:');
                    activeSessions.forEach(session => {
                        console.log(`  - Session ID: ${session.sessionId}`);
                        console.log(`    Phone Number: ${session.phoneNumber || 'Not set'}`);
                        console.log(`    Last Active: ${new Date(session.lastActive).toLocaleString()}`);
                    });
                }
                console.log('='.repeat(100));
            }

            await mongoose.disconnect();
            process.exit(0);
        }

        // If arguments provided, update specific user's points
        if (process.argv.length !== 4) {
            console.error('Usage: node scripts/update-points.js [email] [newPointsBalance]');
            console.error('If no arguments provided, displays all users and their points.');
            process.exit(1);
        }

        const userEmail = process.argv[2];
        const newPoints = parseFloat(process.argv[3]);

        if (isNaN(newPoints)) {
            console.error('Error: <newPointsBalance> must be a valid number.');
            process.exit(1);
        }

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