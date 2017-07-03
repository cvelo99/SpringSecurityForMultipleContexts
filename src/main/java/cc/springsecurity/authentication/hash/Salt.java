package cc.springsecurity.authentication.hash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Thread-save salt generation algorithm. This class is package level access only and should be access via {@link PasswordUtil}
 * 
 * @author carcelc
 * 
 */
class Salt {

    public static final String RNG_ALGORITHM = "SHA1PRNG";

    public static final int DEFAULT_SALT_LENGTH_IN_BYTES = 8;

    /**
     * Get a random salt of the default length.
     * 
     * @see Salt#DEFAULT_SALT_LENGTH
     * @return a byte array of random salt
     */
    public byte[] getRandomSalt() {
        return getRandomSalt(DEFAULT_SALT_LENGTH_IN_BYTES);
    }

    /**
     * Get a random salt of the default length.
     * 
     * @param saltLength
     *            the length of the salt
     * @return a byte array of random salt
     */
    public byte[] getRandomSalt(int saltLength) {

        if (saltLength < 1) {
            throw new IllegalArgumentException("Invalid Length: " + saltLength);
        }

        byte[] salt = new byte[saltLength];

        String saltAlgorithm = RNG_ALGORITHM;
        try {
            SecureRandom.getInstance(saltAlgorithm).nextBytes(salt);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unknown Algorithtm: " + saltAlgorithm, e);
        }

        return salt;

    }

}
