CREATE DATABASE IF NOT EXISTS infosec_grading;
USE infosec_grading;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Plain text intentionally
    role VARCHAR(50) DEFAULT 'student', -- 'student' or 'professor'
    fullname VARCHAR(255) NOT NULL,
    profile_bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS grades (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    course_name VARCHAR(255) NOT NULL,
    grade VARCHAR(2) NOT NULL, -- e.g., 'A', 'B', 'F'
    comments TEXT,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    course_name VARCHAR(100) NOT NULL,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert Dummy Data
INSERT INTO users (username, password, role, fullname, profile_bio) VALUES 
('admin_prof', 'admin123', 'professor', 'Dr. Smith', 'Tenured Professor of Computer Science.'),
('student1', 'password1', 'student', 'John Doe', 'Senior CS Major.'),
('student2', 'ilovecats', 'student', 'Jane Roe', 'Junior IT Major.'),
('guest', 'guest', 'student', 'Guest User', 'Temporary account.');

INSERT INTO grades (student_id, course_name, grade, comments) VALUES
(2, 'INFOSEC 101', 'B', 'Good understanding, needs work on labs.'),
(2, 'DATA STRUCT 202', 'A', 'Excellent performance.'),
(3, 'INFOSEC 101', 'F', 'Missed final exam.'),
(3, 'WEB DEV 300', 'A', 'Great project submission.');

INSERT INTO feedback (username, course_name, comment) VALUES
('student1', 'INFOSEC 101', 'This course was incredibly informative!'),
('student2', 'WEB DEV 300', 'Loved the hands-on project.');
