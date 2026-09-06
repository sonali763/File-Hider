package views;

import dao.DataDAO;
import model.Data;

import java.io.File;
import java.sql.SQLException;
import java.util.List;
import java.util.Scanner;

/**
 * Presentation layer: Logged-in user dashboard.
 * Provides capabilities to inspect encrypted files, hide new files, and restore files.
 */
public class UserView {

    private final String email;
    private final Scanner scanner;

    public UserView(String email, Scanner scanner) {
        this.email = email;
        this.scanner = scanner;
    }

    public UserView(String email) {
        this(email, new Scanner(System.in));
    }

    public void home() {
        boolean inSession = true;
        while (inSession) {
            System.out.println("\n--------------------------------------------------------");
            System.out.println(" VAULT DASHBOARD | User: " + this.email);
            System.out.println("--------------------------------------------------------");
            System.out.println("  1. List All Hidden & Encrypted Files");
            System.out.println("  2. Encrypt and Hide a File");
            System.out.println("  3. Decrypt and Restore a File");
            System.out.println("  4. Logout (Return to Main Menu)");
            System.out.println("  0. Exit Application");
            System.out.println("--------------------------------------------------------");

            int choice = InputHelper.readInt(scanner, "Select an action [0-4]: ", 0, 4);

            switch (choice) {
                case 1 -> showHiddenFiles();
                case 2 -> hideNewFile();
                case 3 -> unhideFile();
                case 4 -> {
                    System.out.println("[✓] Logged out successfully.");
                    inSession = false;
                }
                case 0 -> {
                    System.out.println("\n[✓] Vault session ended. Goodbye!");
                    System.exit(0);
                }
            }
        }
    }

    private void showHiddenFiles() {
        try {
            List<Data> files = DataDAO.getAllFiles(this.email);
            if (files.isEmpty()) {
                System.out.println("\n[i] Your vault is currently empty. No hidden files found.");
                return;
            }

            System.out.println("\n--- CURRENTLY ENCRYPTED & HIDDEN FILES ---");
            System.out.printf("%-6s | %-28s | %-12s | %s%n", "ID", "FILE NAME", "SIZE", "ORIGINAL PATH");
            System.out.println("-------+------------------------------+--------------+----------------------------------");
            for (Data file : files) {
                System.out.printf("%-6d | %-28s | %-12s | %s%n",
                        file.getId(),
                        truncate(file.getFileName(), 28),
                        file.getFormattedSize(),
                        file.getPath());
            }
        } catch (SQLException e) {
            System.err.println("[X] Error retrieving files from vault: " + e.getMessage());
        }
    }

    private void hideNewFile() {
        System.out.println("\n--- ENCRYPT AND HIDE A FILE ---");
        String filePath = InputHelper.readNonEmptyString(scanner, "Enter absolute file path to hide: ");

        File file = new File(filePath);
        if (!file.exists()) {
            System.out.println("[!] Error: Specified file does not exist: " + filePath);
            return;
        }
        if (!file.isFile()) {
            System.out.println("[!] Error: Specified path is a directory or special device, not a file.");
            return;
        }
        if (!file.canRead()) {
            System.out.println("[!] Error: File cannot be read (permission denied).");
            return;
        }

        System.out.println("[*] Encrypting file using AES-256-GCM...");
        Data data = new Data(0, file.getName(), file.getAbsolutePath(), this.email);

        try {
            boolean success = DataDAO.hideFile(data);
            if (success) {
                System.out.println("[✓] SUCCESS: File successfully encrypted, stored in vault, and deleted from disk.");
            }
        } catch (Exception e) {
            System.err.println("[X] Failed to encrypt/hide file: " + e.getMessage());
        }
    }

    private void unhideFile() {
        try {
            List<Data> files = DataDAO.getAllFiles(this.email);
            if (files.isEmpty()) {
                System.out.println("\n[i] No files in vault to restore.");
                return;
            }

            showHiddenFiles();
            int fileId = InputHelper.readInt(scanner, "\nEnter the ID of the file to decrypt and restore: ", 1, Integer.MAX_VALUE);

            boolean fileFound = files.stream().anyMatch(f -> f.getId() == fileId);
            if (!fileFound) {
                System.out.println("[!] ID " + fileId + " not found in your vault.");
                return;
            }

            System.out.println("[*] Decrypting and restoring file...");
            boolean success = DataDAO.unhide(fileId, this.email);
            if (success) {
                System.out.println("[✓] SUCCESS: File verified with GCM authentication tag, decrypted, and restored to disk.");
            }
        } catch (Exception e) {
            System.err.println("[X] Failed to restore file: " + e.getMessage());
        }
    }

    private String truncate(String text, int maxLength) {
        if (text == null) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength - 3) + "...";
    }
}
