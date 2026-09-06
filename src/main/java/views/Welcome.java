package views;

import dao.UserDAO;
import model.User;
import service.GenerateOTP;
import service.SendOTPService;
import service.UserService;

import java.sql.SQLException;
import java.util.Scanner;

/**
 * Presentation layer: Welcome screen, authentication, and user registration.
 */
public class Welcome {

    private final Scanner scanner = new Scanner(System.in);

    public void welcomeScreen() {
        System.out.println("\n========================================================");
        System.out.println("       FILE HIDER - ENTERPRISE SECURITY VAULT           ");
        System.out.println("  Confidentiality • Authenticated AES-256-GCM • 2FA     ");
        System.out.println("========================================================");
        System.out.println("  1. Login with 2FA OTP");
        System.out.println("  2. Create a New Account");
        System.out.println("  0. Exit Application");
        System.out.println("========================================================");

        int choice = InputHelper.readInt(scanner, "Select an option [0-2]: ", 0, 2);

        switch (choice) {
            case 1 -> login();
            case 2 -> signUp();
            case 0 -> {
                System.out.println("\n[✓] Vault session ended. Goodbye!");
                System.exit(0);
            }
        }
    }

    private void login() {
        System.out.println("\n--- USER LOGIN ---");
        String email = InputHelper.readNonEmptyString(scanner, "Enter your registered email: ");

        try {
            if (!UserDAO.isExists(email)) {
                System.out.println("[!] User not found with email: " + email);
                System.out.println("    Please choose option 2 to register.");
                return;
            }

            String genOTP = GenerateOTP.getOTP();
            SendOTPService.sendOTP(email, genOTP);

            String enteredOtp = InputHelper.readNonEmptyString(scanner, "Enter the 6-digit verification code: ");
            if (genOTP.equals(enteredOtp.trim())) {
                System.out.println("[✓] Authentication successful! Loading your vault...");
                new UserView(email, scanner).home();
            } else {
                System.out.println("[X] Authentication failed: Invalid verification code.");
            }

        } catch (SQLException ex) {
            System.err.println("[X] Database error during login: " + ex.getMessage());
        }
    }

    private void signUp() {
        System.out.println("\n--- NEW USER REGISTRATION ---");
        String email = InputHelper.readNonEmptyString(scanner, "Enter your email address: ");

        try {
            // Verify if user already exists BEFORE generating OTP
            if (UserDAO.isExists(email)) {
                System.out.println("[!] An account with this email already exists.");
                System.out.println("    Please choose option 1 from the main menu to login.");
                return;
            }

            String name = InputHelper.readNonEmptyString(scanner, "Enter your full name: ");
            String genOTP = GenerateOTP.getOTP();
            SendOTPService.sendOTP(email, genOTP);

            String enteredOtp = InputHelper.readNonEmptyString(scanner, "Enter the 6-digit verification code: ");
            if (genOTP.equals(enteredOtp.trim())) {
                User user = new User(name, email);
                int response = UserService.saveUser(user);

                switch (response) {
                    case 1 -> {
                        System.out.println("[✓] User registered successfully! You can now log in.");
                    }
                    case 0 -> {
                        System.out.println("[!] User already exists.");
                    }
                    default -> {
                        System.out.println("[X] Registration failed due to a database error.");
                    }
                }
            } else {
                System.out.println("[X] Registration failed: Invalid verification code.");
            }

        } catch (SQLException ex) {
            System.err.println("[X] Database error during registration: " + ex.getMessage());
        }
    }
}
