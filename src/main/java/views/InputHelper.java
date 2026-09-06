package views;

import java.util.Scanner;

/**
 * Robust terminal input helper.
 * Prevents NumberFormatException crashes and validates CLI inputs.
 */
public class InputHelper {

    /**
     * Safely reads an integer within a specified range from the console.
     */
    public static int readInt(Scanner scanner, String prompt, int min, int max) {
        while (true) {
            System.out.print(prompt);
            String input = scanner.nextLine().trim();
            try {
                int value = Integer.parseInt(input);
                if (value >= min && value <= max) {
                    return value;
                }
                System.out.printf("[!] Please enter a number between %d and %d.%n", min, max);
            } catch (NumberFormatException e) {
                System.out.println("[!] Invalid input. Please enter a valid number.");
            }
        }
    }

    /**
     * Safely reads a non-empty string from the console.
     */
    public static String readNonEmptyString(Scanner scanner, String prompt) {
        while (true) {
            System.out.print(prompt);
            String input = scanner.nextLine().trim();
            if (!input.isEmpty()) {
                // Strip surrounding quotes if dragged-and-dropped in terminal
                if ((input.startsWith("\"") && input.endsWith("\"")) || 
                    (input.startsWith("'") && input.endsWith("'"))) {
                    input = input.substring(1, input.length() - 1).trim();
                }
                return input;
            }
            System.out.println("[!] Input cannot be empty. Please try again.");
        }
    }
}
