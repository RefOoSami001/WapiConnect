const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { OAuth2Client } = require('google-auth-library');

// Initialize Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware to verify JWT token
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            throw new Error();
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate.' });
    }
};

// Google Authentication route
router.post('/google', async (req, res) => {
    try {
        const { token } = req.body;

        // Verify Google token
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();

        // Extract user data from Google payload
        const { sub: googleId, email, name, picture } = payload;

        // Check if user exists
        let user = await User.findOne({ googleId });

        if (!user) {
            // Check if email already exists
            const emailUser = await User.findOne({ email });

            if (emailUser) {
                // Link Google account to existing email account
                emailUser.googleId = googleId;
                emailUser.picture = picture;
                await emailUser.save();
                user = emailUser;
            } else {
                // Create new user
                user = new User({
                    email,
                    name,
                    googleId,
                    picture
                });
                await user.save();
            }
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const jwtToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            token: jwtToken,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                picture: user.picture
            }
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(401).json({ error: 'Invalid Google token' });
    }
});

// Signup route
router.post('/signup', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Create new user
        const user = new User({
            email,
            password,
            name
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name
            }
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login route
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                picture: user.picture
            }
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Get current user route
router.get('/me', auth, async (req, res) => {
    res.json({
        user: {
            id: req.user._id,
            email: req.user.email,
            name: req.user.name,
            picture: req.user.picture
        }
    });
});

module.exports = { router, auth }; 