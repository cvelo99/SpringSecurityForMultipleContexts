package cc.springsecurity.authentication.hash;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.stereotype.Component;

/**
 * Facade (maybe) pattern to get to our password utils. Should be replaced with {@link PasswordHashing}
 * 
 * @author carcelc
 * 
 */
@Component
public final class PasswordUtil {

    private Base64.Decoder decoder;
    private Base64.Encoder encoder;

    // TODO update / replace
    // TODO use these:
    // http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#core-services-password-encoding
    // http://docs.spring.io/spring-security/site/docs/current/apidocs/index.html?org/springframework/security/crypto/bcrypt/BCrypt.html

    private static Hash h = new Hash();

    /**
     * Hidden.
     */
    public PasswordUtil() {
        decoder = Base64.getDecoder();
        encoder = Base64.getEncoder();
    }

    /**
     * Converts the user entered string to a byte array then encodes it in base 64.
     * 
     * @param s
     *            a user entered string
     * @return
     */
    public String encodeToString(String s) {
        return encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encode a byte array to a base 64 string.
     * 
     * @param b
     *            a byte[] array of string data
     * @return a base 64 encoded String
     */
    public String encodeToString(byte[] b) {
        return encoder.encodeToString(b);
    }

    /**
     * Decode.
     * 
     * @param base64String
     *            a base64 encoded String
     * @return a byte array of the same data.
     */
    public byte[] decode(String base64String) {
        return decoder.decode(base64String);
    }

    /**
     * Encode the given password generating a random salt.
     * 
     * @param password
     *            the password as text
     * @return {@link HashInfo}
     */
    public HashInfo buildPasswordHash(String password) {
        return h.buildPasswordHash(password);
    }

    /**
     * Hash a password.
     * 
     * @param password
     *            the password to hash
     * @param salt
     *            the salt, or if null, generate new salt. When verifying a password this salt is the known salt. When generating a new
     *            password, this is null and the salt is generated using the default salt algorithm.
     * @return {@link HashInfo}
     * @see {@link Salt}
     */
    public HashInfo buildPasswordHash(String password, byte[] salt) {
        return h.buildPasswordHash(password, salt);
    }

    /**
     * Verifity that the knownPassword is the same as the password with the given salt.
     * 
     * @param knownPassword
     *            the base 64 encoded known password
     * @param salt
     *            the base 64 encoded salt
     * @param password
     *            the text password we are checking.
     * @return
     * @see #verifyPassword(HashInfo, String)
     */
    public boolean verifyPassword(String knownPassword, String salt, String password) {
        HashInfo hi = new HashInfo(salt, knownPassword);
        return h.verifyPassword(hi, password);
    }
}
