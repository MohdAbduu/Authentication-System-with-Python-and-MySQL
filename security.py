import bcrypt
import re
import time
import logging
import base64
import os
import hmac
import hashlib
import pyotp
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


# Password security
def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(stored_hash, provided_password):
    try:
        return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        return False


def is_strong_password(password):
    """Check if password meets strength requirements"""
    if len(password) < 10:
        return False, "Password must be at least 10 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain a lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain a number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain a special character"
    return True, "Password is strong"


# CSRF Protection
def generate_csrf_token():
    """Generate a secure random token for CSRF protection"""
    return base64.b64encode(os.urandom(32)).decode('utf-8')


def verify_csrf_token(stored_token, provided_token):
    """Compare stored and provided CSRF tokens using constant-time comparison"""
    if not stored_token or not provided_token:
        return False
    return hmac.compare_digest(stored_token, provided_token)


# Rate limiting
def check_rate_limit(db, ip_address, max_requests=30, time_window=60):
    """Check if IP is rate-limited based on recent requests"""
    try:
        result = db.execute_query(
            "SELECT * FROM ip_rate_limits WHERE ip_address = %s",
            (ip_address,)
        )
        record = result.fetchone()

        current_time = datetime.now()

        if not record:
            # First request from this IP
            db.execute_query(
                "INSERT INTO ip_rate_limits (ip_address) VALUES (%s)",
                (ip_address,)
            )
            return True

        # Check if IP is blocked
        if record['is_blocked'] and record['blocked_until'] > current_time:
            return False

        # Check if time window has reset
        window_start = record['first_request_time']
        seconds_passed = (current_time - window_start).total_seconds()

        if seconds_passed > time_window:
            # Reset the window
            db.execute_query(
                """UPDATE ip_rate_limits SET 
                   request_count = 1, 
                   first_request_time = %s,
                   last_request_time = %s,
                   is_blocked = FALSE,
                   blocked_until = NULL
                   WHERE ip_address = %s""",
                (current_time, current_time, ip_address)
            )
            return True

        # Increment request count
        new_count = record['request_count'] + 1
        if new_count > max_requests:
            # Block the IP
            block_until = current_time + timedelta(minutes=15)
            db.execute_query(
                """UPDATE ip_rate_limits SET 
                   request_count = %s,
                   last_request_time = %s,
                   is_blocked = TRUE,
                   blocked_until = %s
                   WHERE ip_address = %s""",
                (new_count, current_time, block_until, ip_address)
            )
            logging.warning(f"IP {ip_address} rate limited until {block_until}")
            return False
        else:
            # Update request count
            db.execute_query(
                """UPDATE ip_rate_limits SET 
                   request_count = %s,
                   last_request_time = %s
                   WHERE ip_address = %s""",
                (new_count, current_time, ip_address)
            )
            return True
    except Exception as e:
        logging.error(f"Rate limiting error: {e}")
        # In case of error, allow the request but log it
        return True


# Two-factor authentication
def generate_mfa_secret():
    """Generate a secret key for MFA setup"""
    return pyotp.random_base32()


def generate_mfa_qr_code_url(secret, username, issuer="AbduAuth"):
    """Generate a QR code URL for MFA setup"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(username, issuer_name=issuer)


def verify_mfa_code(secret, provided_code):
    """Verify a MFA code against the secret"""
    if not secret or not provided_code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(provided_code)


# Session management
def generate_session_token():
    """Generate a secure random session token"""
    return base64.b64encode(os.urandom(48)).decode('utf-8')