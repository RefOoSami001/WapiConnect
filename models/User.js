const mongoose = require('mongoose');
// Remove bcrypt require as it's no longer needed for passwords
// const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    googleId: { // Add googleId field
        type: String,
        unique: true,
        sparse: true // Allows multiple null values but ensures uniqueness for actual googleIds
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: false // Make password optional
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    profilePictureUrl: { // Add field for profile picture URL
        type: String
    },
    pointsBalance: { // Add field for points balance
        type: Number,
        required: true,
        default: 50 // Default points for new users
    },
    apiKey: {
        type: String,
        unique: true,
        sparse: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
});

// Add indexes for frequently queried fields
userSchema.index({ pointsBalance: 1 });
userSchema.index({ lastLogin: 1 });

// Remove password hashing logic
// userSchema.pre('save', async function (next) {
//     if (!this.isModified('password')) return next();
//
//     try {
//         const salt = await bcrypt.genSalt(10);
//         this.password = await bcrypt.hash(this.password, salt);
//         next();
//     } catch (error) {
//         next(error);
//     }
// });

// Remove password comparison method
// userSchema.methods.comparePassword = async function (candidatePassword) {
//     return bcrypt.compare(candidatePassword, this.password);
// };

module.exports = mongoose.model('User', userSchema); 