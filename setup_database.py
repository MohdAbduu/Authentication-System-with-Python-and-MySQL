from auth_system.database import DatabaseManager
import logging
import mysql.connector

logging.basicConfig(filename='auth_system.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def setup_database():
    db = None
    try:
        db = DatabaseManager()
        existing_tables = []
        created_tables = []

        # List of tables to create
        tables = [
            ("users", """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    failed_attempts INT DEFAULT 0,
                    last_failed_attempt TIMESTAMP NULL,
                    account_locked BOOLEAN DEFAULT FALSE,
                    account_locked_until TIMESTAMP NULL,
                    password_last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    require_password_change BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret VARCHAR(255) NULL,
                    UNIQUE INDEX idx_username (username),
                    INDEX idx_email (email)
                )
            """),
            ("ip_rate_limits", """
                CREATE TABLE IF NOT EXISTS ip_rate_limits (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    request_count INT DEFAULT 1,
                    first_request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_blocked BOOLEAN DEFAULT FALSE,
                    blocked_until TIMESTAMP NULL,
                    INDEX (ip_address)
                )
            """),
            ("password_history", """
                CREATE TABLE IF NOT EXISTS password_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """),
            ("user_sessions", """
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    user_agent VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """),
            ("login_attempts", """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255),
                    ip_address VARCHAR(45) NOT NULL,
                    user_agent VARCHAR(255),
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT FALSE,
                    INDEX (ip_address),
                    INDEX (username)
                )
            """)
        ]

        # Check which tables already exist
        result = db.execute_query("SHOW TABLES")
        existing_table_names = [record['Tables_in_abdu_db'] for record in result.fetchall()]

        # Create tables that don't exist
        for table_name, create_query in tables:
            try:
                if table_name in existing_table_names:
                    existing_tables.append(table_name)
                    continue

                db.execute_query(create_query)
                created_tables.append(table_name)
            except mysql.connector.Error as err:
                if err.errno == 1050:  # Table already exists
                    existing_tables.append(table_name)
                else:
                    raise

        if existing_tables:
            print(f"Tables already exist: {', '.join(existing_tables)}")

        if created_tables:
            print(f"Created tables: {', '.join(created_tables)}")

        if not created_tables and not existing_tables:
            print("No tables were created or found.")

        logging.info("Database setup completed successfully")
        print("Database setup complete!")

    except Exception as e:
        logging.error(f"Database setup error: {e}")
        print(f"Error setting up database: {str(e)}")
    finally:
        if db:
            db.close()


def add_missing_columns():
    try:
        db = DatabaseManager()

        columns = [
            ("failed_attempts", "INT DEFAULT 0"),
            ("last_failed_attempt", "TIMESTAMP NULL"),
            ("account_locked", "BOOLEAN DEFAULT FALSE"),
            ("account_locked_until", "TIMESTAMP NULL"),
            ("last_login", "TIMESTAMP NULL"),
            ("mfa_enabled", "BOOLEAN DEFAULT FALSE"),
            ("mfa_secret", "VARCHAR(255) NULL")
        ]

        for column_name, column_def in columns:
            try:
                db.execute_query(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}")
                print(f"Added column: {column_name}")
            except mysql.connector.Error as err:
                if err.errno == 1060:  # Duplicate column error
                    print(f"Column {column_name} already exists")
                else:
                    raise

        print("Added all missing columns successfully!")

    except Exception as e:
        print(f"Error adding columns: {str(e)}")
    finally:
        if db:
            db.close()





if __name__ == "__main__":
    setup_database()
    add_missing_columns()