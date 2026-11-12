import sqlite3
import hashlib
import hmac
import secrets
import re
import getpass
from contextlib import contextmanager


DB_NAME = "secure_notes.db"
PBKDF2_ITERATIONS = 600_000


class ValidationError(Exception):
    pass


class AuthenticationError(Exception):
    pass


def validate_username(username):
    if not isinstance(username, str):
        raise ValidationError("Invalid username.")

    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
        raise ValidationError(
            "Username must be 3-30 characters and use letters, "
            "numbers, dots, underscores or hyphens."
        )

    return username


def validate_password(password):
    if not isinstance(password, str):
        raise ValidationError("Invalid password.")

    if len(password) < 12 or len(password) > 256:
        raise ValidationError(
            "Password must contain 12-256 characters."
        )

    if not password.strip():
        raise ValidationError("Password cannot be empty.")

    return password


def validate_title(title):
    if not isinstance(title, str):
        raise ValidationError("Invalid title.")

    title = title.strip()

    if not title or len(title) > 100:
        raise ValidationError(
            "Title must contain 1-100 characters."
        )

    return title


def validate_content(content):
    if not isinstance(content, str):
        raise ValidationError("Invalid note content.")

    if not content.strip() or len(content) > 5000:
        raise ValidationError(
            "Note content must contain 1-5000 characters."
        )

    return content


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return salt, password_hash


def verify_password(password, salt, stored_hash):
    _, calculated_hash = hash_password(password, salt)

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


class SecureNotesManager:

    def __init__(self, db_path=DB_NAME):
        self.db_path = db_path
        self.initialize_database()

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")

        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize_database(self):
        with self.connection() as conn:

            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)

    def register(self, username, password):

        username = validate_username(username)
        password = validate_password(password)

        salt, password_hash = hash_password(password)

        try:
            with self.connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO users
                    (username, salt, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (username, salt, password_hash)
                )

                return cursor.lastrowid

        except sqlite3.IntegrityError:
            raise ValidationError(
                "Registration could not be completed."
            )

    def authenticate(self, username, password):

        username = validate_username(username)
        password = validate_password(password)

        with self.connection() as conn:
            user = conn.execute(
                """
                SELECT id, salt, password_hash
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        if user is None:
            raise AuthenticationError(
                "Invalid username or password."
            )

        if not verify_password(
            password,
            user["salt"],
            user["password_hash"]
        ):
            raise AuthenticationError(
                "Invalid username or password."
            )

        return user["id"]

    def add_note(self, user_id, title, content):

        title = validate_title(title)
        content = validate_content(content)

        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO notes (user_id, title, content)
                VALUES (?, ?, ?)
                """,
                (user_id, title, content)
            )

            return cursor.lastrowid

    def list_notes(self, user_id):

        with self.connection() as conn:
            notes = conn.execute(
                """
                SELECT id, title
                FROM notes
                WHERE user_id = ?
                ORDER BY id DESC
                """,
                (user_id,)
            ).fetchall()

        return notes

    def get_note(self, note_id, user_id):

        with self.connection() as conn:
            note = conn.execute(
                """
                SELECT id, user_id, title, content
                FROM notes
                WHERE id = ? AND user_id = ?
                """,
                (note_id, user_id)
            ).fetchone()

        return note

    def delete_note(self, note_id, user_id):

        with self.connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM notes
                WHERE id = ? AND user_id = ?
                """,
                (note_id, user_id)
            )

            return cursor.rowcount > 0


def notes_menu(app, user_id):

    while True:
        print("\n--- SECURE NOTES MENU ---")
        print("1. Add note")
        print("2. List notes")
        print("3. View note")
        print("4. Delete note")
        print("5. Logout")

        choice = input("Enter your choice: ").strip()

        try:

            if choice == "1":
                title = input("Enter note title: ")
                content = input("Enter note content: ")

                note_id = app.add_note(
                    user_id, title, content
                )

                print("Note saved successfully.")
                print("Note ID:", note_id)

            elif choice == "2":
                notes = app.list_notes(user_id)

                if not notes:
                    print("No notes found.")
                else:
                    print("\nYour notes:")
                    for note in notes:
                        print(
                            f"ID: {note['id']} | "
                            f"Title: {note['title']}"
                        )

            elif choice == "3":
                note_id = int(input("Enter note ID: "))
                note = app.get_note(note_id, user_id)

                if note:
                    print("\nTitle:", note["title"])
                    print("Content:", note["content"])
                else:
                    print("Note not found.")

            elif choice == "4":
                note_id = int(input("Enter note ID: "))

                if app.delete_note(note_id, user_id):
                    print("Note deleted successfully.")
                else:
                    print("Note not found.")

            elif choice == "5":
                print("Logged out successfully.")
                break

            else:
                print("Invalid choice.")

        except (ValueError, ValidationError):
            print("Invalid input. Please check your entries.")

        except Exception:
            print("Something went wrong. Please try again.")


def main():

    app = SecureNotesManager()

    while True:

        print("\n===== SECURE NOTES MANAGER =====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        try:

            if choice == "1":
                username = input("Create username: ")
                password = getpass.getpass(
                    "Create password: "
                )

                app.register(username, password)
                print("Registration successful.")

            elif choice == "2":
                username = input("Username: ")
                password = getpass.getpass("Password: ")

                user_id = app.authenticate(
                    username, password
                )

                print("Login successful.")
                notes_menu(app, user_id)

            elif choice == "3":
                print("Thank you for using Secure Notes Manager.")
                break

            else:
                print("Invalid choice.")

        except ValidationError as error:
            print(error)

        except AuthenticationError:
            print("Invalid username or password.")

        except Exception:
            print("Something went wrong. Please try again.")


if __name__ == "__main__":
    main()