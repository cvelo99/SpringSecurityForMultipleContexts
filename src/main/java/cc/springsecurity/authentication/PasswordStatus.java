package cc.springsecurity.authentication;

/**
 * Represents the different states of a password in the db.
 * 
 * @author carcelc
 * 
 */
public enum PasswordStatus {
    /**
     * The password is fine, no need to prompt them
     */
    CHECK_OK,
    /**
     * The password expired.
     */
    PASSWORD_EXPIRED,
    /**
     * The password will soon expire.
     */
    PASSWORD_SOON_TO_EXPIRE;
}
