package cc.springsecurity.authentication.sso;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Interface for storing sso information.
 * 
 * @author Chris Carcel
 *
 */
public interface SsoStorage {

    /**
     * Called from the pre-authentication filter, find the user in sso storage.
     * 
     * @param value
     * @return {@link CcPrincipal} or null if not found.
     */
    public abstract UserDetails findUser(String unid);

    /**
     * Called on authentication success, store the user in sso storage.
     * 
     * @param unid
     * @param auth
     */
    public abstract void storeUser(String unid, Authentication auth);

    /**
     * Remove the user from the Sso storage, invalidating their session.
     * 
     * @param unid
     */
    public abstract void removeUser(String unid);

}
