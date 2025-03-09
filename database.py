import mysql.connector
from mysql.connector import pooling
import logging
from config import DB_CONFIG
import time

# Set up logging
logging.basicConfig(filename='auth_system.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class DatabaseManager:
    _pool = None
    _MAX_RETRIES = 3
    _RETRY_DELAY = 0.5  # seconds

    @classmethod
    def get_connection_pool(cls, pool_size=10):
        if cls._pool is None:
            try:
                cls._pool = pooling.MySQLConnectionPool(
                    pool_name="auth_pool",
                    pool_size=pool_size,
                    pool_reset_session=True,
                    **DB_CONFIG
                )
                logging.info("Database connection pool created")
            except mysql.connector.Error as err:
                logging.error(f"Failed to create connection pool: {err}")
                raise
        return cls._pool

    def __init__(self):
        self.connection = None
        self.cursor = None
        self._connect()

    def _connect(self):
        """Establish database connection with retry logic"""
        retries = 0
        while retries < self._MAX_RETRIES:
            try:
                self._pool = self.get_connection_pool()
                self.connection = self._pool.get_connection()
                self.cursor = self.connection.cursor(dictionary=True, buffered=True)
                # Set session timeout
                self.cursor.execute("SET SESSION wait_timeout=28800")
                # Set connection to use UTF-8
                self.cursor.execute("SET NAMES utf8mb4")
                return
            except mysql.connector.Error as err:
                retries += 1
                if retries >= self._MAX_RETRIES:
                    logging.error(f"Database connection failed after {retries} attempts: {err}")
                    raise
                logging.warning(f"Database connection attempt {retries} failed: {err}. Retrying...")
                time.sleep(self._RETRY_DELAY * retries)

    def reconnect_if_needed(self):
        """Check connection and reconnect if closed"""
        try:
            self.cursor.execute("SELECT 1")
        except (mysql.connector.errors.OperationalError,
                mysql.connector.errors.ProgrammingError,
                mysql.connector.errors.InterfaceError):
            logging.info("Database connection lost, reconnecting...")
            self.close()
            self._connect()

    def execute_query(self, query, params=None):
        """Execute a query with retry logic"""
        for attempt in range(self._MAX_RETRIES):
            try:
                self.reconnect_if_needed()
                self.cursor.execute(query, params or ())
                self.connection.commit()
                return self.cursor
            except mysql.connector.Error as err:
                if attempt < self._MAX_RETRIES - 1:
                    logging.warning(f"Query execution attempt {attempt + 1} failed: {err}. Retrying...")
                    time.sleep(self._RETRY_DELAY * (attempt + 1))
                    self.reconnect_if_needed()
                else:
                    self.connection.rollback()
                    logging.error(f"Query execution failed after {attempt + 1} attempts: {err}")
                    raise

    def execute_many(self, query, params_list):
        """Execute a query multiple times with different parameters"""
        try:
            self.reconnect_if_needed()
            self.cursor.executemany(query, params_list)
            self.connection.commit()
            return self.cursor
        except mysql.connector.Error as err:
            self.connection.rollback()
            logging.error(f"Batch query execution failed: {err}")
            raise

    def close(self):
        """Close cursor and connection properly"""
        try:
            if hasattr(self, 'cursor') and self.cursor:
                self.cursor.close()
            if hasattr(self, 'connection') and self.connection:
                self.connection.close()
        except Exception as e:
            logging.error(f"Error closing database connection: {e}")