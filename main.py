from getpass import getpass
import time
import re
import logging
import os
from datetime import datetime, timedelta
import socket

import mysql

from auth_system.database import DatabaseManager
from auth_system.security import (hash_password, verify_password, is_strong_password,
                                  generate_csrf_token, verify_csrf_token, check_rate_limit,
                                  generate_mfa_secret, generate_mfa_qr_code_url, verify_mfa_code,
                                  generate_session_token)

# Security settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 15 * 60  # 15 minutes in seconds
PASSWORD_HISTORY_LIMIT = 5
PASSWORD_MAX_AGE_DAYS = 90
SESSION_TIMEOUT_MINUTES = 30

# Setup logging
logging.basicConfig(filename='auth_system.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global session data
active_session = {
    'user_id': None,
    'username': None,
    'csrf_token': None,
    'session_token': None,
    'created_at': None
}


def get_client_ip():
    """Get client IP address (simplified version)"""
    return "127.0.0.1"  # Replace with actual client IP in production


def main_menu():
    print("\n=== Abdu Auth System ===")
    if active_session['user_id']:
        print(f"Logged in as: {active_session['username']}")
        print("1. View Profile")
        print("2. Change Password")
        print("3. Setup 2FA")
        print("4. Check 2FA Status")
        print("5. Enable 2FA")
        print("6. Logout")
        print("7. Exit")
    else:
        print("1. Login")
        print("2. Create Account")
        print("3. Reset Password")
        print("4. Exit")
    return input("Choose option: ")


def login():
    username = input("Username: ")
    password = input("Password: ")
    ip_address = get_client_ip()
    success = False  # Initialize success flag

    try:
        db = DatabaseManager()

        # Rate limiting check
        if not check_rate_limit(db, ip_address):
            print("Too many login attempts. Please try again later.")
            # Record failed attempt due to rate limit
            db.execute_query(
                """INSERT INTO login_attempts 
                   (username, ip_address, attempt_time, success)
                   VALUES (%s, %s, CURRENT_TIMESTAMP, FALSE)""",
                (username, ip_address)
            )
            return

        result = db.execute_query(
            """SELECT id, username, password_hash,
               CAST(mfa_enabled AS SIGNED) as mfa_enabled,
               mfa_secret
               FROM users WHERE username = %s""",
            (username,)
        )

        user_data = result.fetchone()

        if user_data and verify_password(user_data['password_hash'], password):
            mfa_enabled = bool(user_data.get('mfa_enabled', 0))
            has_mfa_secret = user_data.get('mfa_secret') is not None

            # MFA verification if enabled
            if mfa_enabled and has_mfa_secret:
                mfa_code = input("Enter 2FA code from your authenticator app: ")
                if not verify_mfa_code(user_data['mfa_secret'], mfa_code):
                    # Record failed MFA attempt
                    db.execute_query(
                        """INSERT INTO login_attempts 
                           (username, ip_address, attempt_time, success)
                           VALUES (%s, %s, CURRENT_TIMESTAMP, FALSE)""",
                        (username, ip_address)
                    )
                    print("Invalid 2FA code!")
                    return

            # Login successful
            success = True
            session_token = generate_session_token()
            csrf_token = generate_csrf_token()
            expires_at = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)

            # Update session
            db.execute_query(
                """INSERT INTO user_sessions
                   (user_id, session_token, ip_address, expires_at)
                   VALUES (%s, %s, %s, %s)""",
                (user_data['id'], session_token, ip_address, expires_at)
            )

            # Update user's last login
            db.execute_query(
                """UPDATE users SET last_login = CURRENT_TIMESTAMP
                   WHERE id = %s""",
                (user_data['id'],)
            )

            # Update active session
            active_session.update({
                'user_id': user_data['id'],
                'username': user_data['username'],
                'csrf_token': csrf_token,
                'session_token': session_token,
                'created_at': datetime.now()
            })

            print("\n=== Login successful! ===")
        else:
            print("Invalid credentials!")
            success = False

        # Record login attempt
        db.execute_query(
            """INSERT INTO login_attempts 
               (username, ip_address, attempt_time, success)
               VALUES (%s, %s, CURRENT_TIMESTAMP, %s)""",
            (username, ip_address, success)
        )

    except Exception as e:
        logging.error(f"Login error: {str(e)}", exc_info=True)
        print("An error occurred. Please try again.")
    finally:
        if 'db' in locals():
            db.close()

def create_account():
    username = input("New username: ")

    # Validate username
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        print("Username must be 3-20 characters and contain only letters, numbers, and underscores.")
        return

    password = input("New password: ")
    confirm_password = input("Confirm password: ")

    if password != confirm_password:
        print("Passwords don't match!")
        return

    # Check password strength
    is_strong, message = is_strong_password(password)
    if not is_strong:
        print(f"Password is not strong enough: {message}")
        return

    try:
        db = DatabaseManager()

        # Rate limiting check
        if not check_rate_limit(db, get_client_ip()):
            print("Too many requests. Please try again later.")
            return

        # Check if username already exists
        result = db.execute_query("SELECT id FROM users WHERE username = %s", (username,))
        if result.fetchone():
            print("Username already exists!")
            return

        # Create the account
        hashed_password = hash_password(password)

        # Insert user without password_last_changed
        db.execute_query(
            """INSERT INTO users
               (username, password_hash)
               VALUES (%s, %s)""",
            (username, hashed_password)
        )

        # Get user ID for password history
        result = db.execute_query("SELECT id FROM users WHERE username = %s", (username,))
        user = result.fetchone()

        # Add password to history
        db.execute_query(
            "INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)",
            (user['id'], hashed_password)
        )

        print("Account created successfully!")
        print("You can now login with your new credentials.")

    except Exception as e:
        logging.error(f"Account creation error: {e}", exc_info=True)
        print(f"Error: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()




def change_password(user_id=None):
    if not user_id and not active_session['user_id']:
        print("You must be logged in to change your password.")
        return False

    user_id = user_id or active_session['user_id']

    try:
        db = DatabaseManager()

        # Get current password for verification
        current_password = input("Current password: ")

        result = db.execute_query(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        user_data = result.fetchone()

        if not verify_password(user_data['password_hash'], current_password):
            print("Current password is incorrect!")
            return False

        # Get and validate new password
        new_password = input("New password: ")
        confirm_password = input("Confirm new password: ")

        if new_password != confirm_password:
            print("Passwords don't match!")
            return False

        # Check password strength
        is_strong, message = is_strong_password(new_password)
        if not is_strong:
            print(f"Password is not strong enough: {message}")
            return False

        # Check password history
        result = db.execute_query(
            """SELECT password_hash FROM password_history
               WHERE user_id = %s
               ORDER BY changed_at DESC
               LIMIT %s""",
            (user_id, PASSWORD_HISTORY_LIMIT)
        )

        for record in result:
            if verify_password(record['password_hash'], new_password):
                print("Cannot reuse one of your previous passwords!")
                return False

        # Update password
        new_hash = hash_password(new_password)
        db.execute_query(
            """UPDATE users
               SET password_hash = %s,
               password_last_changed = CURRENT_TIMESTAMP,
               require_password_change = FALSE
               WHERE id = %s""",
            (new_hash, user_id)
        )

        # Add to password history
        db.execute_query(
            "INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)",
            (user_id, new_hash)
        )

        print("Password changed successfully!")
        return True

    except Exception as e:
        logging.error(f"Password change error: {e}")
        print("An error occurred. Please try again.")
        return False
    finally:
        if 'db' in locals():
            db.close()



def update_database_schema():
    """Update database schema to add missing columns for 2FA"""
    try:
        print("Updating database schema to support 2FA...")
        db = DatabaseManager()

        # Check if mfa_enabled column exists
        try:
            result = db.execute_query("SELECT mfa_enabled FROM users LIMIT 1")
            print("Column 'mfa_enabled' already exists.")
        except mysql.connector.Error:
            print("Adding 'mfa_enabled' column...")
            db.execute_query("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE")
            print("Column 'mfa_enabled' added successfully.")

        # Check if mfa_secret column exists
        try:
            result = db.execute_query("SELECT mfa_secret FROM users LIMIT 1")
            print("Column 'mfa_secret' already exists.")
        except mysql.connector.Error:
            print("Adding 'mfa_secret' column...")
            db.execute_query("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255) NULL")
            print("Column 'mfa_secret' added successfully.")

        print("Database schema updated successfully!")
        return True

    except Exception as e:
        logging.error(f"Database schema update error: {e}", exc_info=True)
        print(f"Error updating database schema: {str(e)}")
        return False
    finally:
        if 'db' in locals():
            db.close()


def setup_2fa():
    if not active_session['user_id']:
        print("You must be logged in to set up 2FA.")
        return

    # Update database schema first
    if not update_database_schema():
        print("Cannot setup 2FA without required database columns.")
        return



    try:
        db = DatabaseManager()

        # Check if user exists and get current MFA status
        result = db.execute_query(
            "SELECT username FROM users WHERE id = %s",
            (active_session['user_id'],)
        )
        user_data = result.fetchone()

        if not user_data:
            print("User account not found.")
            return

        # Generate new 2FA secret
        mfa_secret = generate_mfa_secret()

        # Create setup instructions - no QR code in terminal, just the secret
        print("\n== Two-Factor Authentication Setup ==")
        print("1. Install Google Authenticator or a similar TOTP app on your mobile device")
        print("2. In your app, select 'Add account' or '+' icon")
        print("3. Choose 'Enter setup key' or 'Manual entry'")
        print("4. Enter the following details:")
        print(f"   Account name: {active_session['username']}@AbduAuth")
        print(f"   Your secret key: {mfa_secret}")
        print("   Time-based: Yes")

        # Verify setup
        verification_code = input("\nEnter the 6-digit code from your authenticator app: ")
        if not verify_mfa_code(mfa_secret, verification_code):
            print("Invalid code! 2FA setup failed.")
            return

        # Save the 2FA secret - with column existence check
        try:
            # First try with both columns
            db.execute_query(
                "UPDATE users SET mfa_secret = %s, mfa_enabled = TRUE WHERE id = %s",
                (mfa_secret, active_session['user_id'])
            )
        except mysql.connector.Error:
            # If that fails, try with just mfa_secret
            try:
                db.execute_query(
                    "UPDATE users SET mfa_secret = %s WHERE id = %s",
                    (mfa_secret, active_session['user_id'])
                )
            except mysql.connector.Error as e:
                logging.error(f"Database columns for 2FA may not exist: {e}")
                print("Your database schema needs to be updated to support 2FA.")
                return

        print("\n2FA has been successfully enabled!")
        print("You will need to enter a code from your authenticator app each time you log in.")

    except Exception as e:
        logging.error(f"2FA setup error: {str(e)}", exc_info=True)
        print(f"2FA setup error: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()


def logout():
    if not active_session['user_id']:
        print("You are not logged in.")
        return

    try:
        db = DatabaseManager()

        # Invalidate session in database
        db.execute_query(
            "UPDATE user_sessions SET is_active = FALSE WHERE session_token = %s",
            (active_session['session_token'],)
        )

        # Clear session data
        active_session.update({
            'user_id': None,
            'username': None,
            'csrf_token': None,
            'session_token': None,
            'created_at': None
        })

        print("Logged out successfully.")

    except Exception as e:
        logging.error(f"Logout error: {e}")
        print("An error occurred during logout.")
    finally:
        if 'db' in locals():
            db.close()



def check_2fa_status():
    if not active_session['user_id']:
        print("You must be logged in to check 2FA status.")
        return

    try:
        db = DatabaseManager()
        result = db.execute_query(
            """SELECT mfa_enabled, mfa_secret
               FROM users WHERE id = %s""",
            (active_session['user_id'],)
        )
        user_data = result.fetchone()

        if user_data:
            print(f"2FA Status: {'Enabled' if user_data.get('mfa_enabled') else 'Disabled'}")
            print(f"2FA Secret exists: {'Yes' if user_data.get('mfa_secret') else 'No'}")
        else:
            print("User not found.")

    except Exception as e:
        print(f"Error checking 2FA status: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()

def enable_2fa():
    if not active_session['user_id']:
        print("You must be logged in to enable 2FA.")
        return

    try:
        db = DatabaseManager()
        db.execute_query(
            "UPDATE users SET mfa_enabled = TRUE WHERE id = %s AND mfa_secret IS NOT NULL",
            (active_session['user_id'],)
        )
        print("2FA has been enabled.")
    except Exception as e:
        print(f"Error enabling 2FA: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()




if __name__ == "__main__":
    while True:
        try:
            choice = main_menu()

            if active_session['user_id']:  # Logged in menu
                if choice == '1':
                    print("View Profile - Feature not implemented")
                elif choice == '2':
                    change_password()
                elif choice == '3':
                    setup_2fa()
                elif choice == '4':
                    check_2fa_status()  # New option
                elif choice == '5':
                    enable_2fa()  # New option
                elif choice == '6':
                    logout()
                elif choice == '7':
                    break
                else:
                    print("Invalid choice!")
            else:  # Not logged in menu
                if choice == '1':
                    login()
                elif choice == '2':
                    create_account()
                elif choice == '3':
                    print("Reset Password - Feature not implemented")
                elif choice == '4':
                    break
                else:
                    print("Invalid choice!")

        except KeyboardInterrupt:
            print("\nExiting safely...")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            print("An unexpected error occurred. Please try again.")