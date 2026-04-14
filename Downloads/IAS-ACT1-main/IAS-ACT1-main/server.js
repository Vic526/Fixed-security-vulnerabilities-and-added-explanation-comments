const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const multer = require('multer');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
// SECURITY ENHANCEMENT: CORS policy locked down to localhost domain only
// Blocks malicious websites from making cross-origin requests to our API
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(cookieParser());

// SECURITY ENHANCEMENT: Implemented rate limiting mechanism for authentication endpoints
// Thwarts automated brute force attacks by limiting request frequency per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: "Too many login attempts, please try again later"
});

// SECURITY ENHANCEMENT: Deployed CSRF token system for state-modifying operations
// Generates unique tokens to verify request authenticity and prevent forgery
const csrfProtection = csrf({ cookie: true });
// SECURITY ENHANCEMENT: Hardened cookie security with httpOnly flag enabled
// Stops client-side scripts from hijacking session cookies through XSS attacks
app.use(session({
    secret: process.env.SESSION_SECRET || 'insecure_default_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Note: Should be true in production with HTTPS
        httpOnly: true // Prevents JavaScript access to cookies
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
// SECURITY ENHANCEMENT: Implemented strict file type validation for upload functionality
// Scans MIME types to block executable files and allow only image formats
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
const db = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'infosec_activity'
});
// SECURITY ENHANCEMENT: Migrated to parameterized database queries and secure password verification
// Eliminates SQL injection vectors and implements proper bcrypt hash comparison
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    // Query user by username ONLY (not password)
    const query = 'SELECT * FROM users WHERE username = ?';

    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error(err); // Server-side logging for debugging
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }

        if (results.length > 0) {
            // Compare provided password with stored hash using bcrypt
            const match = await bcrypt.compare(password, results[0].password);
            if(match) {
                req.session.user = results[0];
                res.json({ success: true, message: 'Logged in successfully', user: results[0] });
            } else {
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});
// SECURITY ENHANCEMENT: Applied parameterized queries and HTML output sanitization
// Prevents database injection and neutralizes reflected XSS attack vectors
app.get('/api/search', (req, res) => {
    const searchQuery = req.query.q;
    const sql = 'SELECT username, bio FROM users WHERE username LIKE ?';

    db.query(sql, [`%${searchQuery}%`], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        if (req.headers.accept && req.headers.accept.includes('text/html')) {
            // Sanitize searchQuery to prevent reflected XSS
            const safeQuery = searchQuery.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            return res.send(`<h1>Search Results for: ${safeQuery}</h1> <pre>${JSON.stringify(results)}</pre>`);
        }

        res.json({ query: searchQuery, results });
    });
});
// SECURITY ENHANCEMENT: Enforced mandatory authentication for forum message creation
// Blocks anonymous users from spamming or contaminating message threads
app.post('/api/messages', csrfProtection, (req, res) => {
    // Block the action entirely if no session exists!
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'You must be logged in to post on the forum.' });
    }
    
    const username = req.session.user.username;
    const content = req.body.content;
    
    // Sanitize content to prevent stored XSS attacks
    const sanitizedContent = content.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    const sql = 'INSERT INTO messages (username, content) VALUES (?, ?)';

    db.query(sql, [username, sanitizedContent], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json({ success: true, message: 'Message posted!' });
    });
});

app.get('/api/messages', (req, res) => {
    db.query('SELECT * FROM messages ORDER BY created_at DESC', (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});
// SECURITY ENHANCEMENT: Eliminated direct object reference by using session-based user identification
// Stops attackers from enumerating and accessing other users' profile data
app.get('/api/profile', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = req.session.user.id; // Only use trusted session ID

    db.query('SELECT id, username, bio, is_admin FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(results[0]);
    });
});
// SECURITY ENHANCEMENT: Restricted profile modification to non-privileged fields only
// Prevents privilege escalation by ignoring admin status in update requests
app.post('/api/profile/update', csrfProtection, (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const userId = req.session.user.id;
    const { bio } = req.body; // Only extract allowed field: bio

    const sql = 'UPDATE users SET bio = ? WHERE id = ?';
    db.query(sql, [bio, userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json({ success: true, message: 'Profile updated' });
    });
});
// SECURITY ENHANCEMENT: Added rigorous IP address validation before system command execution
// Neutralizes command injection attempts through strict format verification
app.post('/api/network-ping', (req, res) => {
    const ip = req.body.ip;
    
    // Validate IP address format to prevent command injection
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return res.json({ success: false, output: 'Invalid IP address format.' });
    }
    
    exec(`ping -n 1 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            return res.json({ success: false, output: stderr || error.message });
        }
        res.json({ success: true, output: stdout });
    });
});
app.post('/api/upload-avatar', csrfProtection, upload.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const newPath = path.join(__dirname, 'public/uploads', req.file.originalname);
    fs.renameSync(req.file.path, newPath);

    res.json({ success: true, message: 'File uploaded!', path: `/uploads/${req.file.originalname}` });
});
// SECURITY ENHANCEMENT: Implemented filename sanitization using basename extraction
// Prevents directory traversal attacks by stripping path manipulation characters
app.get('/api/download', (req, res) => {
    const filename = req.query.file;
    const safeFilename = path.basename(filename); // Strips "../" and other traversal characters
    const filePath = path.join(__dirname, 'public/uploads', safeFilename);

    res.download(filePath, (err) => {
        if (err) {
            console.error(err);
            res.status(500).send('File not found or access denied');
        }
    });
});
// SECURITY ENHANCEMENT: Removed sensitive password data from user directory listings
// Mitigates information leakage by excluding credentials from public user data
app.get('/api/users', (req, res) => {
    db.query('SELECT id, username, bio, is_admin FROM users', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json(results);
    });
});
// SECURITY ENHANCEMENT: Established URL whitelist blocking internal network ranges
// Stops Server-Side Request Forgery by preventing access to internal infrastructure
app.post('/api/fetch-url', async (req, res) => {
    const targetUrl = req.body.url;
    
    try {
        const url = new URL(targetUrl);
        
        // Block internal/private IP ranges to prevent SSRF
        const hostname = url.hostname;
        if (hostname === 'localhost' || 
            hostname === '127.0.0.1' || 
            hostname.startsWith('192.168.') ||
            hostname.startsWith('10.') ||
            hostname.startsWith('172.') ||
            hostname.startsWith('169.254.')) {
            return res.status(400).json({ error: 'Access to internal resources is not allowed.' });
        }
        
        // Only allow HTTP/HTTPS protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are allowed.' });
        }
        
        const response = await axios.get(targetUrl);
        res.send(response.data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error fetching URL.' });
    }
});
// SECURITY ENHANCEMENT: Implemented strict redirect URL validation and domain whitelisting
// Prevents open redirect phishing attacks by only allowing trusted destinations
app.get('/api/redirect', (req, res) => {
    const targetUrl = req.query.url;
    
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL parameter is required.' });
    }
    
    // Only allow relative paths (starting with /) or specific trusted domains
    if (targetUrl.startsWith('/') || targetUrl.startsWith('http://localhost:3000') || targetUrl.startsWith('http://127.0.0.1:3000')) {
        return res.redirect(targetUrl);
    }
    
    // Block external redirects to prevent phishing
    res.status(400).json({ error: 'External redirects are not allowed.' });
});

app.listen(port, () => {
    console.log(`Vulnerable App is learning on http://localhost:${port}`);
    console.log('Ensure your XAMPP Apache and MySQL are running!');
});
