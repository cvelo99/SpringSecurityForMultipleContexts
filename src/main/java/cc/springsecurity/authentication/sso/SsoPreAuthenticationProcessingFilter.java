package cc.springsecurity.authentication.sso;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;

import cc.springsecurity.authorization.RolesFinder;
import cc.springsecurity.config.AbstractSecurityConfig;
import cc.springsecurity.config.CcWebAuthenticationDetailsSource;

/**
 * Pre-Authentication processing filter. Look for the {@link AbstractSecurityConfig#cookieInformation()} cookie and if found load the
 * {@link Authentication} from there. Used for SSO across web applications. Configured in {@link AbstractSecurityConfig} .
 * 
 * @author Chris Carcel
 *
 */
@Component
public class SsoPreAuthenticationProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static Logger LOG = LoggerFactory.getLogger(SsoPreAuthenticationProcessingFilter.class);

    private static boolean trace;

    static {
        trace = LOG.isTraceEnabled();
        LOG.trace("trace enabled for SsoPreAuthenticationProcessingFilter");
    }

    @Autowired
    private SsoAuthenticationManager ssoAuthenticationManager;

    private SsoStorage ssoStorage;

    @Autowired
    private CcWebAuthenticationDetailsSource ccWebAuthenticationDetailsSource;

    private SsoCookieInformation cookieInformation;

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {

        if (trace) {
            LOG.trace("SsoPreAuthenticationProcessingFilter, getPreAuthenticatedPrincipal start");
        }

        Validate.isTrue(null != cookieInformation, "cookieInformation cannot be null, be sure to call setCookieInformation");

        String ssoUnid = ssoUnid(request);

        if (null != ssoUnid) {

            if (trace) {
                LOG.trace("Have ssoUnid: " + ssoUnid);
            }

            UserDetails userDetails = ssoStorage.findUser(ssoUnid);

            if (trace) {
                LOG.trace("returning " + userDetails);
            }

            return userDetails;

        } else {

            if (trace) {
                LOG.trace("returning null");
            }

            return null;
        }
    }

    private String ssoUnid(HttpServletRequest request) {
        if (null != request.getCookies()) {

            // does cookie exist?

            for (Cookie c : request.getCookies()) {
                if (cookieInformation.name().equals(c.getName())) {
                    return c.getValue();
                }
            }

        }
        return null;
    }

    /**
     * Per the javadocs, this should not return null. We do not use it, so we return an empty string.
     */
    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "";
    }

    @Override
    public void afterPropertiesSet() {
        setAuthenticationManager(ssoAuthenticationManager);
        setAuthenticationDetailsSource(ccWebAuthenticationDetailsSource);
        super.afterPropertiesSet();
    }

    public SsoPreAuthenticationProcessingFilter setRolesFinder(RolesFinder rolesFinder) {
        this.ssoAuthenticationManager.setRolesFinder(rolesFinder);
        return this;
    }

    public SsoPreAuthenticationProcessingFilter setCookieInformation(SsoCookieInformation cookieInformation) {
        this.cookieInformation = cookieInformation;
        return this;
    }

    public SsoPreAuthenticationProcessingFilter setSsoStorage(SsoStorage ssoStorage) {
        this.ssoStorage = ssoStorage;
        return this;
    }

}
