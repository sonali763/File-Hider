import views.Welcome;

/**
 * Main application bootstrap for File Hider Security Application.
 */
public class Main {
    public static void main(String[] args) {
        Welcome welcome = new Welcome();
        while (true) {
            welcome.welcomeScreen();
        }
    }
}
