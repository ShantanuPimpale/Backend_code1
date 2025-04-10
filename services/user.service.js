// user.service.js
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const userRepository = require('../repository/user.repository');
const { encrypt } = require('../config/encryption');
const logger = require('../config/logger');
const { ApiError } = require('../middleware/error.middleware');

const SALT_ROUNDS = 10;

const registerUser = async (userData) => {
    try {
        const {
            first_name,
            last_name,
            DoB,
            industry,
            email,
            password,
            phone_number,
            address,
            preferences
        } = userData;

        // Create consistent hash for email for lookup purposes
        const emailHash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');

        // Create consistent hash for phone number (if provided) for lookup purposes
        const phoneHash = phone_number ?
            crypto.createHash('sha256').update(phone_number).digest('hex') :
            null;

        // Check if user already exists with hashed email
        const existingUserByEmail = await userRepository.findUserByEmailHash(emailHash);
        if (existingUserByEmail) {
            logger.warn(`Registration attempt with existing email: ${email.substring(0, 3)}...`);
            throw new ApiError(409, 'Email already registered');
        }

        // Check if user already exists with hashed phone number (if provided)
        if (phoneHash) {
            const existingUserByPhone = await userRepository.findUserByPhoneHash(phoneHash);
            if (existingUserByPhone) {
                logger.warn(`Registration attempt with existing phone: ${phone_number.substring(0, 3)}...`);
                throw new ApiError(409, 'Phone number already registered');
            }
        }

        try {
            // Encrypt the actual data for storage
            const encryptedEmail = encrypt(email);
            const encryptedPhone = phone_number ? encrypt(phone_number) : null;

            // Hash password
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

            // For address data
            const encryptedAddress = address ? {
                state: address.state ? address.state : null,
                country: address.country ? address.country : null
            } : {};

            // Create new user object with encrypted data and hashed identifiers
            const newUser = await userRepository.createUser({
                first_name: first_name,
                last_name: last_name,
                DoB: DoB,
                industry: industry,
                email: encryptedEmail,
                emailHash: emailHash, // Store the hash for lookup
                password: hashedPassword,
                phone_number: encryptedPhone,
                phoneHash: phoneHash, // Store the hash for lookup
                address: encryptedAddress,
                status: 'inactive',
                email_verified: false,
                preferences: preferences || { notification_opt_in: false },
                provider: 'local',
                created_at: new Date(),
                login_history: []
            });

            try {
                await otpService.generateAndSendOTP(newUser._id, email);
            } catch (otpError) {
                logger.error('Failed to send verification email during registration', {
                    error: otpError.message,
                    stack: otpError.stack,
                    userId: newUser._id
                });
            }

            return newUser;
        } catch (encryptionError) {
            console.error('Encryption failure details:', encryptionError);
            logger.error('Encryption failed during user registration', {
                error: encryptionError.message,
                stack: encryptionError.stack
            });
            throw new ApiError(500, 'Failed to secure user data');
        }
    } catch (error) {
        // If it's already an ApiError, just rethrow it
        if (error instanceof ApiError) {
            throw error;
        }

        // Log and throw appropriate error
        logger.error('User registration failed', {
            error: error.message,
            stack: error.stack
        });

        throw new ApiError(500, error.message || 'Registration failed');
    }
};

const getUserProfile = async (userId) => {
    try {
        const user = await userRepository.findUserById(userId);

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        return user;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('Error retrieving user profile', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Failed to retrieve user profile');
    }
};

const changePassword = async (userId, currentPassword, newPassword) => {
    try {
        // Get full user object with password
        const user = await User.findById(userId);

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        // Verify current password
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            throw new ApiError(401, 'Current password is incorrect');
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        // Update password
        user.password = hashedPassword;
        await user.save();

        return true;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('Password change failed', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Failed to change password');
    }
};

module.exports = {
    registerUser,
    getUserProfile,
    changePassword
};