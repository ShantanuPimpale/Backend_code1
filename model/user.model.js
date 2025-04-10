const mongoose = require('mongoose');

const loginHistorySchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now
    },
    ip: {
        type: String
    },
    device: {
        type: String
    }
}, { _id: false });

const otpSchema = new mongoose.Schema({
    code: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    otpResendCount: { type: Number, default: 0 },
    otpResendTimestamp: { type: Date }
}, { _id: false });

const userSchema = new mongoose.Schema({
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    DoB: { type: Date },
    industry: {
        type: String,
        enum: ['Healthcare', 'Digital Engineering', 'Life science', 'Pharmacy']
    },
    email: { type: String, required: true, unique: true },
    emailHash: {
        type: String,
        required: true,
        index: true 
    },
    password: { type: String },
    phone_number: { type: String },
    phoneHash: {
        type: String,
        required: false,
        index: true
    },
    address: {
        state: { type: String },
        country: { type: String } // ISO 3166-1 Alpha-2
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'banned'],
        default: 'inactive'
    },
    email_verified: {
        type: Boolean,
        default: false
    },
    otp: {
        type: otpSchema,
        index: { expiresAt: 1 }
    },
    preferences: {
        notification_opt_in: { type: Boolean, default: false }
    },
    provider: { type: String, enum: ['local', 'google', 'linkedin'], required: true },
    providerId: { type: String },
    last_login: {
        type: Date
    },
    last_activity: {
        type: Date
    },
    login_history: [loginHistorySchema]
}, {
    timestamps: {
        createdAt: 'created_at',
        updatedAt: 'updated_at'
    }
});

const User = mongoose.model('User', userSchema);
module.exports = User;