
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const logDirectory = path.join(__dirname, 'logs');
const logFile = path.join(logDirectory, 'auth.log');

// Create the logs directory automatically if it doesn't exist.
fs.mkdirSync(logDirectory, { recursive: true });

function logEvent(eventType, status, details = {}) {
    const event = {
        '@timestamp': new Date().toISOString(),
        service: 'myprofile-mfa-api',
        event_type: eventType,
        status,
        request_id: crypto.randomUUID(),
        ...details
    };

    // Prevent sensitive data from accidentally being written to logs.
    delete event.password;
    delete event.code;
    delete event.otp;
    delete event.token;
    delete event.sessionToken;
    delete event.authorization;
    delete event.email;

    try {
        fs.appendFileSync(
            logFile,
            JSON.stringify(event) + '\n',
            { encoding: 'utf8', mode: 0o600 }
        );
    } catch (error) {
        // Avoid logging secrets or request data in this error handler.
        console.error('Failed to write authentication log:', error.message);
    }
}

module.exports = { logEvent };
