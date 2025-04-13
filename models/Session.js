const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    sessionId: {
        type: String,
        required: true,
        unique: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['connecting', 'connected', 'disconnected'],
        default: 'connecting'
    },
    phoneNumber: {
        type: String,
        default: null
    },
    lastActive: {
        type: Date,
        default: Date.now
    }
});

// Add indexes for frequently queried fields
sessionSchema.index({ userId: 1 });
sessionSchema.index({ status: 1 });
sessionSchema.index({ lastActive: 1 });
sessionSchema.index({ userId: 1, status: 1 }); // Compound index for common queries

module.exports = mongoose.model('Session', sessionSchema); 