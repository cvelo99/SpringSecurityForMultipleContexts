package cc.springsecurity.authentication.hash;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Thread safe hash and verify passwords. This class is package level access only and should be access via {@link PasswordUtil}
 * 
 * @author carcelc
 * 
 */
class Hash {

    /**
     * Message Digest Algorithm we use.
     */
    private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-1";

    /**
     * The number of times we encode the password.
     */
    private static final int DEFAULT_ITERATION_COUNT = 1000;

    /**
     * Encode the given password generating a random salt.
     * 
     * @param password
     *            the password
     * @return {@link HashInfo}
     */
    public HashInfo buildPasswordHash(String password) {
        return buildPasswordHash(password, null);
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

        if (null == salt) {
            salt = new Salt().getRandomSalt();
        }

        byte[] passwordBytes = getHash(DEFAULT_ITERATION_COUNT, password, salt);

        Coder c = new Coder();

        String passwordEncoded = c.encodeToString(passwordBytes);

        String saltEncoded = c.encodeToString(salt);

        return new HashInfo(saltEncoded, passwordEncoded);

    }

    /**
     * Verify that the {@link HashInfo#getPassword()} is the the same as the argument password by hashing the argument password with the
     * {@link HashInfo#getSalt()} then comparing them.
     * 
     * @param info
     *            the salt and known password
     * @param password
     *            the password we are confirming
     * @return true if the passwords match, false otherwise.
     */
    public boolean verifyPassword(HashInfo info, String password) {

        Coder c = new Coder();

        byte[] salt = c.decode(info.getSalt());

        byte[] storedPassword = c.decode(info.getPassword());

        byte[] potentialPassword = c.decode(buildPasswordHash(password, salt).getPassword());

        return Arrays.equals(storedPassword, potentialPassword);

    }

    /**
     * From a password, a number of iterations and a salt, returns the corresponding digest
     * 
     * @param iterationNb
     *            int The number of iterations of the algorithm
     * @param password
     *            String The password to encrypt
     * @param salt
     *            byte[] The salt
     * @return byte[] The digested password
     */
    private byte[] getHash(int iterationNb, String password, byte[] salt) {
        try {

            MessageDigest digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
            digest.reset();
            digest.update(salt);
            byte[] input = digest.digest(password.getBytes("UTF-8"));
            for (int i = 0; i < iterationNb; i++) {
                digest.reset();
                input = digest.digest(input);
            }
            return input;
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

}
