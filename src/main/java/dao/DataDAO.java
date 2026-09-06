package dao;

import db.MyConnection;
import model.Data;
import security.CryptoEngine;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for secure file operations.
 * Implements AES-256-GCM authenticated encryption, binary BLOB streaming,
 * and transactional integrity (rollbacks prevent file loss).
 */
public class DataDAO {

    /**
     * Retrieves all encrypted files belonging to a specific user.
     */
    public static List<Data> getAllFiles(String email) throws SQLException {
        String sql = "SELECT id, name, path, email, iv, file_size FROM data WHERE email = ? ORDER BY id DESC";
        List<Data> files = new ArrayList<>();

        try (Connection connection = MyConnection.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String name = rs.getString("name");
                    String path = rs.getString("path");
                    byte[] iv = rs.getBytes("iv");
                    long size = rs.getLong("file_size");
                    files.add(new Data(id, name, path, email, iv, size));
                }
            }
        }
        return files;
    }

    /**
     * Encrypts and hides a file into the database.
     * Uses AES-256-GCM encryption with a unique 12-byte IV and streaming binary BLOB.
     * Transactional: Original file on disk is ONLY deleted if the DB commit succeeds.
     *
     * @param file Data model containing file metadata
     * @return true if file was successfully encrypted and hidden
     */
    public static boolean hideFile(Data file) throws Exception {
        File sourceFile = new File(file.getPath());
        if (!sourceFile.exists() || !sourceFile.isFile()) {
            throw new IOException("File does not exist or is not a valid regular file: " + file.getPath());
        }

        long originalSize = sourceFile.length();
        byte[] iv = CryptoEngine.generateIV();
        SecretKey masterKey = MyConnection.getMasterKey();

        // Create temporary file for encrypted ciphertext
        File tempEncryptedFile = File.createTempFile("vault_enc_", ".tmp");
        tempEncryptedFile.deleteOnExit();

        try {
            // 1. Encrypt raw binary stream using AES-256-GCM
            try (InputStream fis = new FileInputStream(sourceFile);
                 FileOutputStream fos = new FileOutputStream(tempEncryptedFile)) {
                CryptoEngine.encryptStream(fis, fos, masterKey, iv);
            }

            // 2. Persist encrypted payload and metadata inside a database transaction
            String sql = "INSERT INTO data (name, path, email, bin_data, iv, file_size) VALUES (?, ?, ?, ?, ?, ?)";

            try (Connection connection = MyConnection.getConnection()) {
                connection.setAutoCommit(false); // Begin transaction

                try (PreparedStatement ps = connection.prepareStatement(sql);
                     InputStream encIn = new FileInputStream(tempEncryptedFile)) {

                    ps.setString(1, sourceFile.getName());
                    ps.setString(2, sourceFile.getAbsolutePath());
                    ps.setString(3, file.getEmail());
                    ps.setBinaryStream(4, encIn, tempEncryptedFile.length());
                    ps.setBytes(5, iv);
                    ps.setLong(6, originalSize);

                    ps.executeUpdate();
                    connection.commit(); // Commit transaction
                } catch (Exception ex) {
                    connection.rollback(); // Rollback on failure
                    throw ex;
                }
            }

            // 3. Delete original file only after database commit is confirmed
            if (!sourceFile.delete()) {
                System.err.println("[WARN] File was encrypted in database, but could not delete local copy: " + sourceFile.getAbsolutePath());
            }

            return true;
        } finally {
            // Clean up temporary encrypted cache file
            if (tempEncryptedFile.exists()) {
                tempEncryptedFile.delete();
            }
        }
    }

    /**
     * Restores (decrypts) a file from the database back to its original path.
     * Verifies GCM authentication tag for tamper detection.
     *
     * @param id File record ID
     * @param userEmail Owner's email address for authorization
     */
    public static boolean unhide(int id, String userEmail) throws Exception {
        String selectSql = "SELECT name, path, bin_data, iv FROM data WHERE id = ? AND email = ?";
        String deleteSql = "DELETE FROM data WHERE id = ? AND email = ?";

        try (Connection connection = MyConnection.getConnection()) {
            connection.setAutoCommit(false); // Begin transaction

            String originalPath = null;
            byte[] iv = null;
            InputStream encryptedStream = null;

            try (PreparedStatement ps = connection.prepareStatement(selectSql)) {
                ps.setInt(1, id);
                ps.setString(2, userEmail);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        System.out.println("[!] No file found with ID: " + id);
                        return false;
                    }
                    originalPath = rs.getString("path");
                    iv = rs.getBytes("iv");
                    encryptedStream = rs.getBinaryStream("bin_data");
                }
            }

            if (originalPath == null || iv == null || encryptedStream == null) {
                throw new IOException("Corrupted metadata: unable to retrieve file data.");
            }

            File targetFile = new File(originalPath);
            File parentDir = targetFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            // Decrypt binary stream directly to restored file
            SecretKey masterKey = MyConnection.getMasterKey();
            try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                CryptoEngine.decryptStream(encryptedStream, fos, masterKey, iv);
            } catch (Exception ex) {
                // If decryption fails (e.g. tampered data or wrong key), remove corrupt file
                if (targetFile.exists()) {
                    targetFile.delete();
                }
                connection.rollback();
                throw new SecurityException("Cryptographic verification failed: Authentication tag mismatch or corrupted ciphertext.", ex);
            }

            // Remove entry from database
            try (PreparedStatement delPs = connection.prepareStatement(deleteSql)) {
                delPs.setInt(1, id);
                delPs.setString(2, userEmail);
                delPs.executeUpdate();
            }

            connection.commit(); // Commit transaction
            return true;
        }
    }
}
