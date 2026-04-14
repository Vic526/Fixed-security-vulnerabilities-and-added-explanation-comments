CREATE DATABASE IF NOT EXISTS infosec_activity;

USE infosec_activity;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    bio TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert dummy data to make it easier to test
INSERT IGNORE INTO users (username, password, is_admin, bio) VALUES ('admin', 'admin123', TRUE, 'I find vulnerabilities and patch them.');
INSERT IGNORE INTO users (username, password, is_admin, bio) VALUES ('student', 'password1', FALSE, 'Learning how to secure applications.');
INSERT IGNORE INTO users (username, password, is_admin, bio) VALUES ('john_doe', 'johnny', FALSE, 'Regular user checking out the site.');

INSERT IGNORE INTO messages (username, content) VALUES ('admin', 'Welcome to the vulnerable message board! Do not test XSS here. ;)');
