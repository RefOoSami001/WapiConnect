const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const User = require('../models/User'); // Assuming models/User.js path

module.exports = function (passport) {
    passport.use(
        new GoogleStrategy(
            {
                clientID: process.env.GOOGLE_CLIENT_ID, // Use environment variable
                clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Use environment variable
                callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback', // Use environment variable or default
                scope: ['profile', 'email'], // Request profile and email info
            },
            async (accessToken, refreshToken, profile, done) => {
                // profile contains user information from Google
                console.log('Google Profile Received:', profile.id, profile.displayName, profile.emails[0].value);

                const newUser = {
                    googleId: profile.id,
                    email: profile.emails[0].value, // Get the primary email
                    name: profile.displayName,
                    profilePictureUrl: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null // Get profile picture URL
                    // Password is not set here
                };

                try {
                    // Find user by googleId
                    let user = await User.findOne({ googleId: profile.id });

                    if (user) {
                        // User exists, update lastLogin and potentially profile pic
                        user.lastLogin = Date.now();
                        if (newUser.profilePictureUrl && user.profilePictureUrl !== newUser.profilePictureUrl) {
                            user.profilePictureUrl = newUser.profilePictureUrl;
                        }
                        await user.save();
                        console.log('Existing Google user found:', user.email);
                        done(null, user);
                    } else {
                        // Check if user exists by email (maybe they signed up differently before?)
                        user = await User.findOne({ email: newUser.email });
                        if (user) {
                            // User exists with email, link Google ID and add profile pic
                            console.log('Existing user found by email, linking Google ID:', user.email);
                            user.googleId = profile.id;
                            user.lastLogin = Date.now();
                            user.profilePictureUrl = newUser.profilePictureUrl; // Add profile pic URL
                            // Optionally update name if different
                            // user.name = newUser.name;
                            await user.save();
                            done(null, user);
                        } else {
                            // Create new user
                            console.log('Creating new user from Google profile:', newUser.email);
                            user = await User.create(newUser);
                            done(null, user);
                        }
                    }
                } catch (err) {
                    console.error('Error during Google OAuth strategy execution:', err);
                    done(err, null);
                }
            }
        )
    );

    // Serialize user to store in session
    passport.serializeUser((user, done) => {
        done(null, user.id); // Use MongoDB's _id for session storage
    });

    // Deserialize user from session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user); // Provides req.user
        } catch (err) {
            console.error('Error deserializing user:', err);
            done(err, null);
        }
    });
}; 