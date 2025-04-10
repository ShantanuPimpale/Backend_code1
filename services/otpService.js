const crypto = require('crypto');
const nodemailer = require('nodemailer');
const userRepository = require('../repository/user.repository');
const { decrypt } = require('../config/encryption');
const logger = require('../config/logger');
const { ApiError } = require('../middleware/error.middleware');

// OTP configuration
const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 15;
const MAX_OTP_RESEND_COUNT = 3;

// Create a transporter for sending emails
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Generate OTP
const generateOTP = () => {
    // Generate a numeric OTP of specified length
    return crypto.randomInt(100000, 999999).toString().padStart(OTP_LENGTH, '0');
};

// Store OTP in database with expiry time
const storeOTP = async (userId, otp, isResend = false) => {
    try {
        const expiryTime = new Date();
        expiryTime.setMinutes(expiryTime.getMinutes() + OTP_EXPIRY_MINUTES);

        // If this is a resend, we need to increment the resend counter
        let otpData = {
            code: otp,
            expiresAt: expiryTime
        };

        if (isResend) {
            // Get current user to check resend count
            const user = await userRepository.findUserWithOTP(userId);

            // Initialize or increment resend count
            const currentCount = user && user.otp ? (user.otp.otpResendCount || 0) : 0;
            otpData.otpResendCount = currentCount + 1;
            otpData.otpResendTimestamp = new Date();
        } else {
            // Reset resend count for new OTP requests (not resends)
            otpData.otpResendCount = 0;
        }

        await userRepository.storeUserOTP(userId, otpData);
        return true;
    } catch (error) {
        logger.error('Failed to store OTP', {
            error: error.message,
            stack: error.stack,
            userId
        });
        throw new ApiError(500, 'Failed to generate verification code');
    }
};

// Send OTP via email
const sendOTPEmail = async (email, otp) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_FROM || 'noreply@yourdomain.com',
            to: email,
            subject: 'Your Email Verification Code',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Email Verification</h2>
          <p>Thank you for registering with our service. Please use the following verification code to activate your account:</p>
          <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
            ${otp}
          </div>
          <p>This code will expire in ${OTP_EXPIRY_MINUTES} minutes.</p>
          <p>If you did not request this code, please ignore this email.</p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        logger.error('Failed to send OTP email', {
            error: error.message,
            stack: error.stack,
            emailPrefix: email.substring(0, 3)
        });
        throw new ApiError(500, 'Failed to send verification email');
    }
};

// Generate and send OTP for a user
const generateAndSendOTP = async (userId, isResend = false) => {
    try {
        // Get user email
        const user = await userRepository.findUserById(userId);
        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        // Check resend limit if this is a resend request
        if (isResend) {
            // Get current user with OTP data
            const userWithOTP = await userRepository.findUserWithOTP(userId);

            if (userWithOTP.otp && userWithOTP.otp.otpResendCount >= MAX_OTP_RESEND_COUNT) {
                throw new ApiError(429, 'Maximum OTP resend limit reached. Please contact support.');
            }
        }

        // Decrypt email
        const decryptedEmail = decrypt(user.email);

        // Generate new OTP
        const otp = generateOTP();

        // Store OTP in database with resend flag
        await storeOTP(userId, otp, isResend);

        // Send OTP via email
        await sendOTPEmail(decryptedEmail, otp);

        return true;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('OTP generation and sending failed', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Failed to send verification code');
    }
};

// Verify OTP and activate user
const verifyOTPAndActivateUser = async (userId, otpCode) => {
    try {
        // Get stored OTP for user
        const user = await userRepository.findUserWithOTP(userId);

        if (!user || !user.otp) {
            throw new ApiError(404, 'Verification code not found or expired');
        }

        // Check if OTP has expired
        if (new Date() > new Date(user.otp.expiresAt)) {
            await userRepository.removeUserOTP(userId);
            throw new ApiError(400, 'Verification code has expired');
        }

        // Verify OTP code
        if (user.otp.code !== otpCode) {
            throw new ApiError(400, 'Invalid verification code');
        }

        // Mark user as verified and active
        await userRepository.activateUser(userId);

        // Remove used OTP
        await userRepository.removeUserOTP(userId);

        return true;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('OTP verification failed', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Failed to verify code');
    }
};

// Get remaining OTP resend attempts
const getRemainingOTPResendAttempts = async (userId) => {
    try {
        const user = await userRepository.findUserWithOTP(userId);
        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        const currentCount = user.otp ? (user.otp.otpResendCount || 0) : 0;
        return MAX_OTP_RESEND_COUNT - currentCount;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        logger.error('Failed to get remaining OTP attempts', {
            error: error.message,
            stack: error.stack,
            userId
        });

        throw new ApiError(500, 'Failed to check remaining attempts');
    }
};

module.exports = {
    generateAndSendOTP,
    verifyOTPAndActivateUser,
    getRemainingOTPResendAttempts,
    MAX_OTP_RESEND_COUNT
};