# DefendNet / Central Valley University: Student Worksheet

Welcome to the cybersecurity range! This application is designed to look like a realistic modern university portal, but it secretly contains **20 security vulnerabilities** based on the OWASP Top 10. 

Your task for each vulnerability:
1. **Exploit it**: Prove the vulnerability exists.
2. **Fix it**: Modify the `server.js` code to fix the vulnerability and secure the system.

---

## 1. SQL Injection (Login Authentication)
**Where**: `POST /api/login` (in `login.html`)
The login form does not sanitize the username or password inputs, blindly piecing them into a SQL query using string concatenation.

### How to Exploit
1. Go to the **Student Login** page.
2. In the "University ID" field, type: `' OR '1'='1' -- ` (with a trailing space).
3. Type anything into the Password field and click Secure Login.
4. *Result*: You are logged in as the first user in the database (usually admin) without knowing the password!

### How to Fix
Open `server.js` and locate Vulnerability 1. Change the query to use **parameterized queries**, which isolates the strings from the SQL execution engine:
```javascript
// Change this:
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.query(query, (err, results) => { ... });

// To this:
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.query(query, [username, password], (err, results) => { ... });
```

---

## 2. SQL Injection (Search Endpoint)
**Where**: `GET /api/search?q=` 
*Note: This API endpoint exists on the server but may not be directly linked in the UI.*

### How to Exploit
1. Open your browser and navigate directly to: `http://localhost:3000/api/search?q=' OR 1=1 -- `
2. *Result*: The application dumps every single user in the directory!

### How to Fix
Parameterize the search query exactly like you did for the login.
```javascript
const sql = 'SELECT username, bio FROM users WHERE username LIKE ?';
// In SQLite/MySQL, use % around the searchTerm variable
db.query(sql, [`%${searchQuery}%`], (err, results) => { ... });
```

---

## 3. Stored Cross-Site Scripting (XSS)
**Where**: `POST /api/messages` (Campus Life Forum)

### How to Exploit
1. Go to the **Campus Life** page.
2. Assuming you are logged in (or you just post a message normally), type the following in the box: `<script>alert("XSS Payload Executed! Checking Cookies: " + document.cookie)</script>`
3. *Result*: Now, *anyone* who visits the Campus Life page will get a popup executing that code on their machine!

### How to Fix
In `messages.html`, when rendering the content, **do not** use `div.innerHTML`. Use `div.textContent`, which safely escapes all HTML automatically. You can also sanitize on the backend in `server.js` by escaping `<` and `>` before saving to the database.

*Frontend Fix (`messages.html`)*:
```javascript
// Change div.innerHTML rendering to use standard text allocation:
const contentDiv = document.createElement('div');
contentDiv.className = 'msg-content';
contentDiv.textContent = msg.content; // textContent is immune to XSS
div.appendChild(contentDiv);
```

---

## 4. Reflected Cross-Site Scripting (XSS)
**Where**: `GET /api/search?q=`

### How to Exploit
1. To test Reflected XSS, go to: `http://localhost:3000/api/search?q=<script>alert('XSS')</script>`
2. *Result*: The Node server directly reflects the raw script back into the HTML response!

### How to Fix
In `server.js`, you must sanitize `searchQuery` before sending it back in an HTML context.
```javascript
// Basic HTML entity escaping:
const safeQuery = searchQuery.replace(/</g, "&lt;").replace(/>/g, "&gt;");
return res.send(`<h1>Search Results for: ${safeQuery}</h1>...`);
```

---

## 5. Insecure Password Storage
**Where**: `users` database table (and Registration if present).

### How to Exploit
1. Look at the database initialization script (`schema.sql`).
2. *Result*: Passwords are in plain text (`password1`, `admin123`). If a hacker steals the database, they have everyone's passwords immediately.

### How to Fix
You must hash passwords using `bcrypt`.
1. Stop your server and run: `npm install bcrypt`
2. In `server.js`, require it: `const bcrypt = require('bcrypt');`
3. Modify the Login logic to compare hashes rather than plain text strings:
```javascript
// Query the user by username ONLY
const query = 'SELECT * FROM users WHERE username = ?';
db.query(query, [username], async (err, results) => {
    // Then compare the hash
    const match = await bcrypt.compare(password, results[0].password);
    if(match) { /* login success */ }
});
```

---

## 6. Insecure Direct Object Reference (IDOR)
**Where**: `GET /api/profile?id=` (My Portal)

### How to Exploit
1. Log in as the `student` user.
2. Go to "My Portal". 
3. Add `?id=1` to the end of the URL: `http://localhost:3000/profile.html?id=1`
4. *Result*: You bypassed access controls and are now viewing the Admin's private profile information!

### How to Fix
In `server.js`, **ignore** the `id` parameter provided by the user in the URL. Rely strictly on the trusted session ID on the server.
```javascript
// Delete this vulnerable line: 
// const userId = req.query.id || req.session.user.id;

// Replace with this secure enforce:
if (!req.session.user) return res.status(401).send('Unauthorized');
const userId = req.session.user.id; 
```

---

## 7. Privilege Escalation (Mass Assignment)
**Where**: `POST /api/profile/update` (My Portal)

### How to Exploit
1. Log in and go to **My Portal**.
2. Intercept the network request to `/api/profile/update` (using Chrome DevTools Network Tab).
3. Right now, it sends: `{"bio": "My new bio"}`
4. Use the DevTools Console to manually send a fetch request adding `is_admin: 1` or `is_admin: true`:
   ```javascript
   fetch('/api/profile/update', { 
       method: 'POST', 
       headers: {'Content-Type':'application/json'}, 
       body: JSON.stringify({ bio: "Hacked", is_admin: 1 }) 
   })
   ```
5. *Result*: The backend blindly accepts the array/object and updates your `is_admin` column to True!

### How to Fix
Explicitly extract only the variables users are *allowed* to update in `server.js`.
```javascript
const allowedBio = req.body.bio; // Extract ONLY bio
const sql = 'UPDATE users SET bio = ? WHERE id = ?';
db.query(sql, [allowedBio, req.session.user.id], ...);
```

---

## 8. Command Injection
**Where**: `POST /api/network-ping` (IT Support Page)

### How to Exploit
1. Go to the **IT Support** page.
2. In the Wi-Fi Ping tool, instead of typing an IP, type: `127.0.0.1 & dir` (Windows) or `127.0.0.1 ; ls -la` (Linux/Mac).
3. *Result*: The server pings the IP, and then executes your injected command, dumping the entire contents of the server's directory to the screen!

### How to Fix
Never use `exec` with arbitrary user input. 
Validate the IP using regex `/^(?:\d{1,3}\.){3}\d{1,3}$/` before passing it to `exec`.
```javascript
if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
   return res.json({ success: false, output: 'Invalid IP address.' });
}
```

---

## 9. Missing Rate Limiting
**Where**: `POST /api/login`

### How to Exploit
1. A hacker can send 10,000 login attempts per second utilizing a brute-force tool (like Burp Suite Intruder) without being blocked by the server.

### How to Fix
Implement a global rate limiter using the Node package `express-rate-limit`:
```javascript
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: "Too many login attempts, please try again later"
});
app.use('/api/login', loginLimiter);
```

---

## 10. Unrestricted File Upload
**Where**: `POST /api/upload-avatar` (My Portal)

### How to Exploit
1. Go to **My Portal**.
2. Under "Upload Official ID Photo", select a `.js`, `.php` or `.exe` file (e.g. `malware.exe`).
3. *Result*: The file uploads perfectly to `/public/uploads/malware.exe` and you can navigate to it. You just infected the server!

### How to Fix
Implement a file filter in Multer to verify both the file extension and the MIME type.
```javascript
const upload = multer({ 
    dest: 'public/uploads/',
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});
```

---

## 11. Path Traversal (LFI - Local File Inclusion)
**Where**: `GET /api/download?file=`

### How to Exploit
1. Open your browser and go to: `http://localhost:3000/api/download?file=../../../../../../Windows/win.ini`
2. *Result*: The server will bypass the `uploads` folder and download a critical Windows System file directly to your computer!

### How to Fix
Prevent directory traversal by sanitizing the filename using `path.basename`.
```javascript
// path.basename forcibly strips directory traversal characters like "../"
const safeFilename = path.basename(req.query.file);
const filePath = path.join(__dirname, 'public/uploads', safeFilename);
res.download(filePath);
```

---

## 12. Cross-Site Request Forgery (CSRF)
**Where**: `POST /api/profile/update`

### How to Exploit
1. Imagine an attacker creates an evil website (`http://evil.com/hack.html`) with a hidden form pointing to `http://localhost:3000/api/profile/update` that auto-submits.
2. If you visit `evil.com` while logged into the university portal, the attacker forces your browser to update your bio without your consent!

### How to Fix
Install `csurf` and require a unique, unpredictable CSRF token for all state-changing API requests (like POST or DELETE). *Note: Modern apps may also use `SameSite: strict` cookies!*

---

## 13. Security Misconfiguration (Information Leakage)
**Where**: Entire app error handling (e.g., `res.status(500).send(err.message)`)

### How to Exploit
1. Trigger a database error (e.g., typing `'` in the login).
2. *Result*: The server responds with `Database Error: SQL syntax error near ...`. This tells hackers exactly what DB you are using (MySQL) and inner architecture details.

### How to Fix
Never send raw `err.message` objects to the frontend. Log them securely on the server (`console.error`), and send a generic string to the user.
```javascript
if (err) {
    console.error(err); // Server-side log for developers
    return res.status(500).json({ error: 'An internal server error occurred.' });
}
```

---

## 14. Insecure Cookie Configuration
**Where**: `server.js` session middleware

### How to Exploit
1. Open DevTools > Application > Cookies.
2. *Result*: `HttpOnly` is false, meaning our XSS exploit (Vulnerability 3) from earlier can read `document.cookie` securely and steal sessions!

### How to Fix
Modify the `express-session` cookies to strictly enforce HttpOnly.
```javascript
app.use(session({
    cookie: { 
        secure: true, // Requires HTTPS
        httpOnly: true // Restricts JS from accessing cookie data
    }
}));
```

---

## 15. Sensitive Data Exposure
**Where**: `GET /api/users`

### How to Exploit
1. Navigate directly to `http://localhost:3000/api/users`.
2. *Result*: Entire database of users, including their hashed or raw passwords, is exposed publicly.

### How to Fix
When returning user lists, actively select only safe fields, omit passwords entirely.
```javascript
const query = 'SELECT id, username, bio, is_admin FROM users';
```

---

## 16. Server-Side Request Forgery (SSRF)
**Where**: `POST /api/fetch-url` (IT Support Page)

### How to Exploit
1. Go to IT Support's "Cloud Resource Fetcher".
2. Type in an internal network URL, like `http://localhost:3306` (MySQL server) or an AWS Metadata server `http://169.254.169.254/latest/meta-data/`.
3. *Result*: The Node.js server acts as your proxy proxy and bypasses its own firewall to read internal cloud data!

### How to Fix
Implement a strict URL whitelist or blacklist. Block IP addresses resolving back to `127.0.0.1`, `10.x.x.x`, or `169.254.x.x`. Require URLs to be standard HTTP/HTTPS.

---

## 17. XML External Entity (XXE) / Insecure Parsers
**Where**: Absent explicitly here (bypassed for complexity constraints), but relates to parsing untrusted XML/JSON data dynamically without disabling DTDs.

### How to Exploit & Fix
Always ensure robust parsers (`express.json()`) disable entity replacement by default.

---

## 18. Unvalidated Redirects
**Where**: `GET /api/redirect?url=`

### How to Exploit
1. Send a victim a phishing link: `http://localhost:3000/api/redirect?url=http://evil-phishing.com/login`
2. *Result*: The user trusts the `localhost:3000` link, but the server blindly bounces them to the hacker portal!

### How to Fix
Verify that `req.query.url` begins strictly with a single `/` to ensure a relative path, or confirm it exists in a whitelist of trusted university domain names.

---

## 19. Insecure CORS Configuration
**Where**: `server.js` global middleware (`app.use(cors({ origin: '*' }))`)

### How to Exploit
1. `origin: '*'` means *any* website in the world can make an AJAX fetch request to your API and read the resulting data. 

### How to Fix
Lock down your API to only accept requests from your valid frontend domains.
```javascript
app.use(cors({ origin: 'http://localhost:3000' }));
```

---

## 20. Broken Authentication (Session Validation)
**Where**: `POST /api/messages`

### How to Exploit
1. Log out or open a fresh Incognito Browser window.
2. Post a message to the Campus Life Forum.
3. *Result*: It succeeds and attributes it to `Anonymous`! The route fails to actually block unauthenticated users from writing to the database!

### How to Fix
Introduce a mandatory route check inside endpoints that require authentication.
```javascript
app.post('/api/messages', (req, res) => {
    // Block the action entirely if no session exists!
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'You must be logged in to post on the forum.' });
    }
    // ... proceed to query
});
```

---
*End of Worksheet. Do not forget to restart your node server (`npm run dev`) after making fixes to `server.js`.*
