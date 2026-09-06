package db;

import security.CryptoEngine;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Database connection manager and configuration loader.
 * Dynamically reads configuration from config.properties or environment variables.
 */
public class MyConnection {

    private static final Properties config = new Properties();
    private static SecretKey cachedMasterKey = null;

    static {
        loadConfiguration();
    }

    private static void loadConfiguration() {
        File configFile = new File("config.properties");
        if (configFile.exists()) {
            try (InputStream is = new FileInputStream(configFile)) {
                config.load(is);
            } catch (IOException e) {
                System.err.println("[WARN] Could not read config.properties, using defaults/environment.");
            }
        }
    }

    public static String getProperty(String key, String defaultValue) {
        String envKey = key.toUpperCase().replace('.', '_');
        String envVal = System.getenv(envKey);
        if (envVal != null && !envVal.isBlank()) {
            return envVal;
        }
        return config.getProperty(key, defaultValue);
    }

    public static Connection getConnection() throws SQLException {
        String url = getProperty("db.url", "jdbc:mysql://localhost:3306/file_hider_db?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        String user = getProperty("db.username", "root");
        String password = getProperty("db.password", "root");

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC Driver not found on classpath", e);
        }

        return DriverManager.getConnection(url, user, password);
    }

    /**
     * Retrieves the cryptographic master key derived from configuration.
     */
    public static synchronized SecretKey getMasterKey() {
        if (cachedMasterKey == null) {
            String passphrase = getProperty("security.master_key", "FileHiderDefaultMasterKey2026!Secure");
            cachedMasterKey = CryptoEngine.deriveKeyFromPassphrase(passphrase);
        }
        return cachedMasterKey;
    }
}
