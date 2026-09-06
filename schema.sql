-- ==========================================================
-- Database Schema for File Hider Security Application
-- DBMS: MySQL 8.0+
-- Description: Stores user credentials and encrypted file payloads (AES-256-GCM)
-- ==========================================================

CREATE DATABASE IF NOT EXISTS file_hider_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE file_hider_db;

-- ----------------------------------------------------------
-- Table: users
-- Description: Manages registered users and access credentials
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- Table: data
-- Description: Stores encrypted file payloads, GCM IVs, and metadata
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL COMMENT 'Original file name',
    path TEXT NOT NULL COMMENT 'Original absolute path',
    email VARCHAR(150) NOT NULL COMMENT 'Owner user email',
    bin_data LONGBLOB NOT NULL COMMENT 'AES-256-GCM encrypted binary file payload',
    iv VARBINARY(16) NOT NULL COMMENT '12-byte cryptographic Initialization Vector for GCM',
    file_size BIGINT DEFAULT 0 COMMENT 'Original file size in bytes',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_data_email (email),
    CONSTRAINT fk_data_user_email FOREIGN KEY (email) REFERENCES users (email) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
