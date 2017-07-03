package cc.springsecurity.authentication.hash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Hash and compare passwords. This uses the {@link BCryptPasswordEncoder}.
 * 
 * @author Chris Carcel
 * 
 */
@Component
public final class PasswordHashing {

    private BCryptPasswordEncoder passwordEncoder;

    /**
     * Constructor.
     */
    public PasswordHashing() {

        SecureRandom sr;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        BCryptPasswordEncoder enc = new BCryptPasswordEncoder(14, sr);
        this.passwordEncoder = enc;
    }

    /**
     * Encode the given password generating a random salt.
     * 
     * @param password
     *            the password as text
     * @return
     */
    public String buildPasswordHash(String password) {
        return passwordEncoder.encode(password);
    }

    /**
     * Verify that the passwords match.
     * 
     * @param knownPassword
     *            the hashed stored password
     * @param password
     *            the text password we are checking.
     * @return
     */
    public boolean verifyPassword(String knownPassword, String password) {

        return passwordEncoder.matches(password, knownPassword);

    }
}
