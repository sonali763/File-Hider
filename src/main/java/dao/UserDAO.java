package dao;

import db.MyConnection;
import model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Data Access Object for User persistence.
 * Employs indexed SQL queries and try-with-resources for zero connection leaks.
 */
public class UserDAO {

    /**
     * Checks if a user already exists with the given email.
     * Uses an indexed LIMIT 1 query instead of a full table scan.
     */
    public static boolean isExists(String email) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE email = ? LIMIT 1";
        try (Connection connection = MyConnection.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Saves a new user record in the database.
     * Uses explicit column names and try-with-resources.
     */
    public static int saveUser(User user) throws SQLException {
        String sql = "INSERT INTO users (name, email) VALUES (?, ?)";
        try (Connection connection = MyConnection.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, user.getName());
            ps.setString(2, user.getEmail());
            return ps.executeUpdate();
        }
    }

    /**
     * Retrieves a user by their email address.
     */
    public static User getUserByEmail(String email) throws SQLException {
        String sql = "SELECT id, name, email FROM users WHERE email = ? LIMIT 1";
        try (Connection connection = MyConnection.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new User(rs.getInt("id"), rs.getString("name"), rs.getString("email"));
                }
            }
        }
        return null;
    }
}
