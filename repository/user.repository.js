// user.repository.js
const User = require('../model/user.model');
const TokenBlacklist = require('../model/blackListToken.model');

const createUser = async (userData) => {
    return await User.create(userData);
};

const findUserByEmailHash = async (emailHash) => {
    return await User.findOne({ emailHash });
};

const findUserByPhoneHash = async (phoneHash) => {
    return await User.findOne({ phoneHash });
};

const findUserById = async (userId) => {
    return await User.findById(userId).select('-password');
};

const updateUserLastLogin = async (userId, ipAddress = null, deviceInfo = null) => {
    const loginData = {
        timestamp: new Date()
    };

    if (ipAddress) loginData.ip = ipAddress;
    if (deviceInfo) loginData.device = deviceInfo;

    return await User.findByIdAndUpdate(userId, {
        last_login: new Date(),
        $push: { login_history: loginData }
    });
};

const updateUserLastActivity = async (userId) => {
    return await User.findByIdAndUpdate(userId, {
        last_activity: new Date()
    });
};

const blacklistToken = async (token, userId, expiresAt) => {
    // This would require you to have a TokenBlacklist model
    // For simplicity, we're just showing the function signature
    return await TokenBlacklist.create({ token, userId, expiresAt });
};

const storeUserOTP = async (userId, otpData) => {
    return await User.findByIdAndUpdate(userId, {
        otp: otpData
    });
};

const findUserWithOTP = async (userId) => {
    return await User.findById(userId).select('otp');
};

const removeUserOTP = async (userId) => {
    return await User.findByIdAndUpdate(userId, {
        $unset: { otp: "" }
    });
};

const activateUser = async (userId) => {
    return await User.findByIdAndUpdate(userId, {
        status: 'active',
        email_verified: true
    });
};
module.exports = {
    createUser,
    findUserByEmailHash,
    findUserByPhoneHash,
    findUserById,
    updateUserLastLogin,
    updateUserLastActivity,
    blacklistToken,
    storeUserOTP,
    findUserWithOTP,
    removeUserOTP,
    activateUser
};