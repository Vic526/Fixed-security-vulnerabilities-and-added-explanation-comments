# Vulnerable Web Application (Educational Range)

This is an intentionally vulnerable Node.js web application designed for cybersecurity training and education. It contains exactly 20 security vulnerabilities based on the OWASP Top 10, built similarly to a modern university portal.

## ⚠️ Warning
**Do not deploy this application on a public or production server.** It is highly vulnerable and easily exploitable. Only run it on a secure local machine or isolated virtual environment.

---

## 🛠️ Setup Instructions

### 1. Prerequisites
- **Node.js** (v14+ recommended)
- **XAMPP** (or any other local MySQL database server like WAMP or standalone MySQL)

### 2. Database Setup (XAMPP/MySQL)
1. Open **XAMPP Control Panel** and start **Apache** and **MySQL**.
2. Open your browser and navigate to `http://localhost/phpmyadmin` (or use your preferred MySQL client).
3. Import the database schema:
   - Go to the **Import** tab.
   - Choose the file `schema.sql` located in this project root folder.
   - Click **Go** (or Import/Execute). This will automatically create the `infosec_activity` database and populate it with the `users` and `messages` tables, including some dummy data for testing.
   *(Alternatively, you can just paste the contents of `schema.sql` into the SQL tab and click Go).*

### 3. Environment Configuration
Ensure there is a `.env` file present in the root folder. It should look like this (adjust values if your local MySQL uses a different port or has a password for the root user):

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=infosec_activity
SESSION_SECRET=super_secret_key_123
PORT=3000
```

### 4. Running the Application
1. Open your terminal or command prompt in the project's root folder.
2. Install the necessary Node.js dependencies:
   ```bash
   npm install
   ```
3. Start the Node.js application:
   ```bash
   npm run dev
   ```
   *(This uses `nodemon` to automatically restart the server when you make fixes to the code! If you prefer a regular start without auto-reloading, run `npm start`).*
4. Open your browser and go to `http://localhost:3000` to access the vulnerable portal.

---

## 🎓 Learning Objectives
Students using this repository should refer to the accompanying files like `STUDENT_WORKSHEET.md`. The overarching goal is to:
1. **Identify** vulnerabilities in `server.js` and the frontend views.
2. **Exploit** each vulnerability to prove its existence and understand its mechanics.
3. **Fix** the vulnerability securely in the codebase to defend against the attack.
