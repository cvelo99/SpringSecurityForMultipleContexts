package cc.springsecurity.authentication;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import cc.springsecurity.authorization.RolesFinder;
import cc.springsecurity.config.CcWebAuthenticationDetails;
import cc.springsecurity.config.CcPrincipal;
import cc.springsecurity.config.CcPrincipalImpl;
import cc.springsecurity.config.utils.HostName;

/**
 * Abstract base class for our {@link AuthenticationProvider}s. We need only provide an implementation of
 * {@link #validateUser(String, String, CcWebAuthenticationDetails)}, returning null if not found, or an instance of {@link CcPrincipal} if
 * the user authenticated successfully.
 * 
 * @author Chris Carcel
 *
 */
public abstract class AbstractCcUserDetailsAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    protected Logger log = LoggerFactory.getLogger(AbstractCcUserDetailsAuthenticationProvider.class);

    protected boolean trace = log.isTraceEnabled();

    protected RolesFinder rolesFinder;

    @Override
    protected CcPrincipal retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {

        if (trace) {
            log.trace("JdbcAuthenticationProvider, retrieveUser enter");
        }

        Object credentials = authentication.getCredentials();

        CcWebAuthenticationDetails wed = (CcWebAuthenticationDetails) authentication.getDetails();

        CcPrincipal result = validateUser(username, credentials.toString(), wed);

        if (trace) {
            log.trace("retrieveUser done, returning " + result);
        }

        if (null != result) {
            return result;
        } else {
            throw new BadCredentialsException(
                    messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }

    }

    /**
     * Validate the user name and password.
     * 
     * @param username
     *            the user name
     * @param password
     *            the password the user entered
     * @param details
     *            an instance of {@link CcWebAuthenticationDetails} to find information about the host and context to which this user is
     *            authenticating
     * @return an instance of {@link CcPrincipal} if the we could authenticate the user, otherwise null.
     */
    protected abstract CcPrincipal validateUser(String username, String password, CcWebAuthenticationDetails details);

    /**
     * Called when the user successfully authenticated in {@link #validateUser(String, String, CcWebAuthenticationDetails)} . Creates the
     * {@link UsernamePasswordAuthenticationToken} .
     */
    @Override
    protected UsernamePasswordAuthenticationToken createSuccessAuthentication(Object principal, Authentication authentication,
            UserDetails user) {

        CcPrincipalImpl p = (CcPrincipalImpl) principal;

        if (log.isTraceEnabled()) {
            log.trace("createSuccessAuthentication, groups is "
                    + (null == p.getGroups() ? "null" : Arrays.stream(p.getGroups()).collect(Collectors.joining(","))));
        }

        Set<String> roles = rolesFinder.roles(HostName.getHost(), p.getGroups());

        if (log.isTraceEnabled()) {
            log.trace("createSuccessAuthentication, roles is " + roles);
        }

        Set<SimpleGrantedAuthority> authorities = rolesFinder.convertToAuthority(roles);

        if (log.isTraceEnabled()) {
            log.trace("createSuccessAuthentication, authorities is " + authorities);
        }

        return new UsernamePasswordAuthenticationToken(p, null, authorities);
    }

    /**
     * Does nothing.
     * 
     * @param userDetails
     * @param authentication
     * @throws AuthenticationException
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) {
    }

    /**
     * Set the roles finder.
     * 
     * @param rolesFinder
     * @return
     */
    public AbstractCcUserDetailsAuthenticationProvider setRolesFinder(RolesFinder rolesFinder) {
        this.rolesFinder = rolesFinder;
        return this;
    }

}
