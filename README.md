# Week 5 Internship Task: Security Enhancements in Python Applications

## 1. Project Title
**Secure Notes Manager Using Python and SQLite**

## 2. Project Description
The Secure Notes Manager is a command-line application developed using Python and SQLite. It allows users to register, log in, create notes, view their notes, and delete their notes.

The main objective of this project is to improve application security by implementing password hashing, input validation, SQL injection prevention, secure database operations, and user-specific access control.

## 3. Technologies Used
- Python 3
- SQLite3
- hashlib
- hmac
- secrets
- unittest
- Bandit

## 4. Project Structure

```text
week5_security_project/
│
├── secure_notes.py
├── test_secure_notes.py
├── README.md
├── secure_notes.db
└── .venv/
```

## 5. Features

1. User registration.
2. Secure user login.
3. Password hashing using PBKDF2-HMAC-SHA256.
4. Random salt generation for passwords.
5. Create and save personal notes.
6. View saved notes.
7. Delete personal notes.
8. Input validation.
9. SQL injection prevention.
10. User-specific note access.
11. Safe error handling.

## 6. Security Enhancements

### Password Security
Passwords are not stored as plain text. PBKDF2-HMAC-SHA256 is used to generate password hashes with random salts.

### SQL Injection Prevention
Parameterized SQL queries are used instead of directly inserting user input into SQL statements.

### Input Validation
Username, password, note title, and note content are validated before database operations.

### Access Control
Each note is associated with a user ID. Users can only view or delete their own notes.

### Error Handling
The application displays safe error messages instead of exposing database details or internal technical information.

### Database Security
SQLite foreign key constraints are enabled, and database connections are closed after use.

## 7. How to Run the Project

### Step 1: Create a Virtual Environment

```bash
python -m venv .venv
```

### Step 2: Activate the Environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Run the Application

```bash
python secure_notes.py
```

### Step 4: Run Security Tests

```bash
python -m unittest -v test_secure_notes.py
```

### Step 5: Run Bandit Security Scan

```bash
python -m pip install bandit
python -m bandit -r secure_notes.py
```

## 8. Security Testing

The following security tests are included in `test_secure_notes.py`:

- Passwords are not stored as plain text.
- Incorrect passwords are rejected.
- SQL injection-style usernames are rejected.
- SQL-like note content is stored as data.
- One user cannot read another user's notes.
- One user cannot delete another user's notes.
- Empty note titles are rejected.
- Oversized note content is rejected.
- Duplicate usernames are rejected.
- Password hashes use random salts.

## 9. Expected Results

All 10 automated security tests should pass.

Expected test summary:

```text
Ran 10 tests

OK
```

The Bandit scan should be reviewed for any security warnings.

## 10. Limitations

- Note contents are stored without encryption at rest.
- The application does not currently implement multi-factor authentication.
- Account recovery is not implemented.
- Login rate limiting is not implemented.
- This is an educational command-line project, not a production-ready application.

## 11. Conclusion

The Secure Notes Manager demonstrates important Python application security practices. It improves password protection, prevents common SQL injection attacks, validates user input, protects user-specific data, and handles errors safely.

This project helped demonstrate how security enhancements can improve the reliability and protection of a Python application.

---

**Project:** Week 5 – Security Enhancements in Python Applications  
**Application:** Secure Notes Manager  
**Language:** Python  
**Database:** SQLite
