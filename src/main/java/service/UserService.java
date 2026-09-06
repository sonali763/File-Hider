package service;

import dao.UserDAO;
import model.User;

import java.sql.SQLException;

/**
 * Service handling user operations and business validation.
 */
public class UserService {

    /**
     * Registers a user if not already registered.
     *
     * @param user User to save
     * @return 1 if registered successfully, 0 if user already exists, -1 on database failure
     */
    public static int saveUser(User user) {
        try {
            if (UserDAO.isExists(user.getEmail())) {
                return 0; // Already exists
            }
            return UserDAO.saveUser(user); // 1 = inserted
        } catch (SQLException ex) {
            System.err.println("[ERROR] Database error during user registration: " + ex.getMessage());
            return -1;
        }
    }
}
