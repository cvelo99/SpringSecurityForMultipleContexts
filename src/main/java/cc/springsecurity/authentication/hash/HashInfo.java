package cc.springsecurity.authentication.hash;

/**
 * Simple, immutable bean for holding the password and salt in one spot.
 * 
 * @author carcelc
 * 
 */
public class HashInfo {

    private final String salt;

    private final String password;

    /**
     * Setup
     * 
     * @param salt
     *            the salt
     * @param password
     *            the password
     */
    protected HashInfo(String salt, String password) {
        this.salt = salt;
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public String getPassword() {
        return password;
    }

}
