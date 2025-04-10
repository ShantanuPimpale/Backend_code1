// user.controller.js
const userService = require('../services/user.service');
const otpService = require('../services/otpService');
const { validateUserRegistration } = require('../validation/user.validation');
const logger = require('../config/logger');
const { ApiError } = require('../middleware/error.middleware');

const registerUser = async (req, res, next) => {
    try {
        // Validate input data
        const { error } = validateUserRegistration(req.body);
        if (error) {
            // Format validation errors
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message
            }));

            throw new ApiError(400, 'Validation Error', { errors });
        }

        // Log registration attempt (without sensitive data)
        logger.info(`Registration attempt for email: ${req.body.email.substring(0, 3)}...`);

        // Register the user
        const user = await userService.registerUser(req.body);

        try {
            // Initial OTP send is not a resend
            await otpService.generateAndSendOTP(user._id, false);
        } catch (otpError) {
            logger.error('Failed to send verification email during registration', {
                error: otpError.message,
                stack: otpError.stack,
                userId: user._id
            });
            // Continue with registration response even if OTP sending fails
        }

        // Log successful registration
        logger.info(`User registered successfully: ${user._id}`);

        // Return successful response
        res.status(201).json({
            status: 'success',
            message: 'User registered successfully. Please check your email for a verification code.',
            user: {
                id: user._id,
                status: user.status
            }
        });
    } catch (error) {
        // If it's a known error, pass it to the error handler
        if (error instanceof ApiError) {
            return next(error);
        }

        // Handle specific error cases
        if (error.message === 'User already registered') {
            return next(new ApiError(409, 'Email is already registered'));
        }

        // For unexpected errors
        next(new ApiError(500, 'Failed to register user', error));
    }
};

const verifyEmail = async (req, res, next) => {
    try {
        const { userId, otpCode } = req.body;

        if (!userId || !otpCode) {
            throw new ApiError(400, 'User ID and verification code are required');
        }

        // Verify OTP and activate user
        await otpService.verifyOTPAndActivateUser(userId, otpCode);

        res.status(200).json({
            status: 'success',
            message: 'Email verified and account activated successfully'
        });
    } catch (error) {
        if (error instanceof ApiError) {
            return next(error);
        }

        next(new ApiError(500, 'Failed to verify email'));
    }
};

const resendOTP = async (req, res, next) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            throw new ApiError(400, 'User ID is required');
        }

        // Check remaining attempts before sending
        const remainingAttempts = await otpService.getRemainingOTPResendAttempts(userId);

        if (remainingAttempts <= 0) {
            throw new ApiError(429, 'Maximum OTP resend limit reached. Please contact support.');
        }

        // Generate and send new OTP (with resend flag set to true)
        await otpService.generateAndSendOTP(userId, true);

        // Calculate remaining attempts after this resend
        const updatedRemainingAttempts = remainingAttempts - 1;

        res.status(200).json({
            status: 'success',
            message: 'Verification code sent successfully',
            data: {
                remainingAttempts: updatedRemainingAttempts,
                maxAttempts: otpService.MAX_OTP_RESEND_COUNT
            }
        });
    } catch (error) {
        if (error instanceof ApiError) {
            return next(error);
        }

        next(new ApiError(500, 'Failed to send verification code'));
    }
};

const getUserProfile = async (req, res, next) => {
    try {
        const userId = req.user.id;

        // Get user profile
        const user = await userService.getUserProfile(userId);

        res.status(200).json({
            status: 'success',
            data: user
        });
    } catch (error) {
        if (error instanceof ApiError) {
            return next(error);
        }

        next(new ApiError(500, 'Failed to retrieve user profile'));
    }
};

const updateUserProfile = async (req, res, next) => {
    // Implementation for profile updates
    // This would be similar to other controller methods
    res.status(501).json({
        status: 'error',
        message: 'Not implemented yet'
    });
};

const changePassword = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        // Validate input
        if (!currentPassword || !newPassword) {
            throw new ApiError(400, 'Current password and new password are required');
        }

        // Change password
        await userService.changePassword(userId, currentPassword, newPassword);

        res.status(200).json({
            status: 'success',
            message: 'Password changed successfully'
        });
    } catch (error) {
        if (error instanceof ApiError) {
            return next(error);
        }

        next(new ApiError(500, 'Failed to change password'));
    }
};

module.exports = {
    registerUser,
    verifyEmail,
    resendOTP,
    getUserProfile,
    updateUserProfile,
    changePassword
};