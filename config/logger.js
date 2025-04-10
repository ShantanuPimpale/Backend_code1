const winston = require('winston');
const path = require('path');

// Define log file paths
const logDirectory = path.join(__dirname, '../logs');
const userErrorLogFile = path.join(logDirectory, '../logs/usererror.log');
const userExceptionLogFile = path.join(logDirectory, '../logs/userexceptions.log'); // New log file for Plaza exceptions

// Create the Winston logger instance
const logger = winston.createLogger({
    level: 'error', // Only log errors and higher severity
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, stack }) => {
            return `${timestamp} [${level}]: ${message}\nStack: ${stack || 'N/A'}`;
        })
    ),
    transports: [
        // Log user errors to a file
        new winston.transports.File({ filename: userErrorLogFile }),
        ]
});

// Log unhandled exceptions to a separate Plaza exceptions log file
logger.exceptions.handle(
    new winston.transports.File({ filename: userExceptionLogFile })
);

module.exports = logger;
