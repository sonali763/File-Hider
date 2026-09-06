package service;

import java.security.SecureRandom;

/**
 * Cryptographically secure One-Time-Password (OTP) generator.
 * Uses SecureRandom to prevent prediction attacks.
 */
public class GenerateOTP {
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a secure 6-digit OTP token.
     * Range: 100000 - 999999
     */
    public static String getOTP() {
        int otp = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(otp);
    }
}
