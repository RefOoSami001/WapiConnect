const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/User');

// Middleware to verify JWT token
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            throw new Error('No token provided');
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) {
            throw new Error('User not found');
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        console.error('Auth middleware error:', error.message);
        res.status(401).json({ error: 'Please authenticate.' });
    }
};

// Remove Signup route
// router.post('/signup', ...);

// Remove Login route
// router.post('/login', ...);

// --- Google OAuth Routes ---

// 1. Route to start the Google OAuth flow
// User clicks 'Login with Google' -> redirects to Google's consent screen
router.get('/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 2. Google OAuth Callback Route
// After user grants permission, Google redirects back here
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login.html?error=google_auth_failed', session: false }),
    async (req, res) => {
        console.log('Google callback successful, user:', req.user.email);

        try {
            req.user.lastLogin = new Date();
            await req.user.save();

            const payload = { userId: req.user._id };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

            const userData = JSON.stringify({
                id: req.user._id,
                email: req.user.email,
                name: req.user.name,
                profilePictureUrl: req.user.profilePictureUrl,
                pointsBalance: req.user.pointsBalance
            });

            res.redirect(`/dashboard.html?token=${token}&user=${encodeURIComponent(userData)}`);

        } catch (error) {
            console.error('Error during Google callback processing:', error);
            res.redirect('/login.html?error=callback_processing_failed');
        }
    }
);

// --- End Google OAuth Routes ---

// Get current user route
router.get('/me', auth, async (req, res) => {
    res.json({
        user: {
            id: req.user._id,
            email: req.user.email,
            name: req.user.name
        }
    });
});

// Optional: Logout route if using sessions (we are using JWT, so client just deletes token)
// router.get('/logout', (req, res) => {
//     req.logout();
//     res.redirect('/');
// });

module.exports = { router, auth }; 