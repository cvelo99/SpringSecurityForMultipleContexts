package cc.springsecurity.authorization;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import cc.springsecurity.authentication.HostServletContext;

/**
 * Find roles.
 * 
 * @author Chris Carcel
 *
 */
public interface RolesFinder {

    /**
     * Find the roles.
     * 
     * @param hostServletContext
     * @param groups
     * @return
     */
    Set<String> roles(HostServletContext hostServletContext, String[] groups);

    /**
     * Convert roles to authorities.
     * 
     * @param roles
     *            the set of string roles, not prefixed by ROLE_
     * @return {@link SimpleGrantedAuthority} objects, prefixed by ROLE_
     */
    public default Set<SimpleGrantedAuthority> convertToAuthority(Collection<String> roles) {
        Set<SimpleGrantedAuthority> result;
        if (null != roles) {
            result = new HashSet<SimpleGrantedAuthority>(roles.size());
            for (String role : roles) {
                result.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        } else {
            result = null;
        }
        return result;
    }

}
