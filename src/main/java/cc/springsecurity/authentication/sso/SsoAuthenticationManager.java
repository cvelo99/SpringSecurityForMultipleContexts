package cc.springsecurity.authentication.sso;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import cc.springsecurity.authentication.HostServletContext;
import cc.springsecurity.authorization.RolesFinder;
import cc.springsecurity.config.CcWebAuthenticationDetails;
import cc.springsecurity.config.CcPrincipal;
import cc.springsecurity.config.utils.HostName;

/**
 * Used (and required) by the {@link SsoPreAuthenticationProcessingFilter} . Create a {@link UsernamePasswordAuthenticationToken} using the
 * roles found by the {@link RolesFinder} .
 * 
 * @author Chris Carcel
 *
 */
@Component
public class SsoAuthenticationManager implements AuthenticationManager {

    private static Logger LOG = LoggerFactory.getLogger(SsoAuthenticationManager.class);

    private static boolean trace;

    static {
        trace = LOG.isTraceEnabled();
        LOG.trace("trace enabled for SsoAuthentication manager");
    }

    private RolesFinder rolesFinder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (trace) {
            LOG.trace("SsoAuthenticationManager, authenticate start");
            LOG.trace("authentication class is " + authentication.getClass().getName());
        }

        PreAuthenticatedAuthenticationToken token;

        Object objectDetails = authentication.getDetails();
        Validate.notNull(objectDetails, "authentication.getDetails() is null");
        if (!(objectDetails instanceof CcWebAuthenticationDetails)) {
            throw new IllegalStateException(
                    "object " + objectDetails + " is not CcWebAuthenticationDetails, it is " + objectDetails.getClass().getName());
        }

        Object objectPrincipal = authentication.getPrincipal();
        Validate.notNull(objectDetails, "CcWebAuthenticationDetails.getPrincipal() is null");
        if (!(objectPrincipal instanceof CcPrincipal)) {
            throw new IllegalStateException("CcWebAuthenticationDetails.getPrincipal() should be an instanceof CcPrincipal but is "
                    + objectDetails + " and is class " + objectPrincipal.getClass().getName());
        }
        CcPrincipal p = (CcPrincipal) objectPrincipal;

        HostServletContext v = HostName.getHost();
        Set<String> roles = rolesFinder.roles(v, p.getGroups());

        Collection<SimpleGrantedAuthority> authorities;
        if (null == roles || roles.isEmpty()) {
            authorities = Collections.emptySet();
        } else {
            authorities = rolesFinder.convertToAuthority(roles);
        }

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(p, null, authorities);

        return result;

    }

    public SsoAuthenticationManager setRolesFinder(RolesFinder rolesFinder) {
        this.rolesFinder = rolesFinder;
        return this;
    }

}
