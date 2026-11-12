import os
import sqlite3
import tempfile
import unittest

from secure_notes import (
    SecureNotesManager,
    ValidationError,
    AuthenticationError,
    hash_password
)


class SecurityTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.db_path = os.path.join(
            self.temp_dir.name,
            "test.db"
        )

        self.app = SecureNotesManager(self.db_path)

        self.user1 = self.app.register(
            "student_one",
            "StrongPassword123!"
        )

        self.user2 = self.app.register(
            "student_two",
            "AnotherPassword456!"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_password_is_not_stored_as_plaintext(self):

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT salt, password_hash
                FROM users
                WHERE username = ?
                """,
                ("student_one",)
            ).fetchone()

        salt, stored_hash = row

        self.assertNotEqual(
            stored_hash,
            b"StrongPassword123!"
        )

        self.assertEqual(len(salt), 16)
        self.assertEqual(len(stored_hash), 32)

    def test_wrong_password_is_rejected(self):

        with self.assertRaises(AuthenticationError):
            self.app.authenticate(
                "student_one",
                "WrongPassword123!"
            )

    def test_sql_injection_username_is_rejected(self):

        with self.assertRaises(ValidationError):
            self.app.authenticate(
                "' OR '1'='1",
                "SomePassword123!"
            )

    def test_sql_like_content_is_stored_as_data(self):

        malicious_text = "'; DROP TABLE users; --"

        note_id = self.app.add_note(
            self.user1,
            "Security Test",
            malicious_text
        )

        note = self.app.get_note(
            note_id,
            self.user1
        )

        self.assertIsNotNone(note)
        self.assertEqual(
            note["content"],
            malicious_text
        )

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

        self.assertEqual(count, 2)

    def test_other_user_cannot_read_note(self):

        note_id = self.app.add_note(
            self.user1,
            "Private Note",
            "Secret information"
        )

        note = self.app.get_note(
            note_id,
            self.user2
        )

        self.assertIsNone(note)

    def test_other_user_cannot_delete_note(self):

        note_id = self.app.add_note(
            self.user1,
            "Private Note",
            "Secret information"
        )

        deleted = self.app.delete_note(
            note_id,
            self.user2
        )

        self.assertFalse(deleted)

        note = self.app.get_note(
            note_id,
            self.user1
        )

        self.assertIsNotNone(note)

    def test_empty_title_is_rejected(self):

        with self.assertRaises(ValidationError):
            self.app.add_note(
                self.user1,
                "",
                "Some content"
            )

    def test_oversized_content_is_rejected(self):

        long_content = "A" * 5001

        with self.assertRaises(ValidationError):
            self.app.add_note(
                self.user1,
                "Large Note",
                long_content
            )

    def test_duplicate_username_is_rejected(self):

        with self.assertRaises(ValidationError):
            self.app.register(
                "student_one",
                "DifferentPassword789!"
            )

    def test_password_hashes_use_random_salts(self):

        salt1, hash1 = hash_password(
            "StrongPassword123!"
        )

        salt2, hash2 = hash_password(
            "StrongPassword123!"
        )

        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)


if __name__ == "__main__":
    unittest.main(verbosity=2)