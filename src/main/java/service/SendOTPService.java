package service;

import db.MyConnection;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

/**
 * Two-Factor Authentication Service.
 * Dispatches one-time verification tokens via SMTP (e.g. Gmail).
 * Features an intelligent offline/demo fallback if SMTP credentials are not configured.
 */
public class SendOTPService {

    public static boolean sendOTP(String email, String genOTP) {
        String from = MyConnection.getProperty("mail.from", "");
        String password = MyConnection.getProperty("mail.password", "");
        String host = MyConnection.getProperty("mail.smtp.host", "smtp.gmail.com");
        String port = MyConnection.getProperty("mail.smtp.port", "465");
        String sslEnable = MyConnection.getProperty("mail.smtp.ssl.enable", "true");
        String auth = MyConnection.getProperty("mail.smtp.auth", "true");

        // Demo / Fallback Mode when SMTP credentials are not configured
        if (from == null || from.isBlank() || password == null || password.isBlank()) {
            System.out.println("------------------------------------------------------------");
            System.out.println("[DEMO MODE] SMTP credentials not configured in config.properties.");
            System.out.println(">> Verification Code for [" + email + "]: " + genOTP);
            System.out.println("------------------------------------------------------------");
            return true;
        }

        Properties properties = new Properties();
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", port);
        properties.put("mail.smtp.ssl.enable", sslEnable);
        properties.put("mail.smtp.auth", auth);

        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(from, password);
            }
        });

        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from, "File Hider Vault"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(email));
            message.setSubject("Security Verification Code - File Hider Vault");
            message.setText("Hello,\n\nYour one-time security verification code is: " + genOTP + 
                           "\n\nThis code will expire shortly. If you did not request this, please ignore.\n\n-- File Hider Security System");

            Transport.send(message);
            System.out.println("[INFO] Verification code sent successfully to " + email);
            return true;
        } catch (Exception mex) {
            System.err.println("[ERROR] Failed to send email via SMTP: " + mex.getMessage());
            System.out.println("[FALLBACK] Verification Code for [" + email + "]: " + genOTP);
            return false;
        }
    }
}
