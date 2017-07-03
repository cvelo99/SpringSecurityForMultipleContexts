package cc.springsecurity.authentication.sso;

import org.apache.commons.lang3.Validate;

/**
 * Find the cookie name and domain using system properties.
 * 
 * @author Chris Carcel
 *
 */
public class SystemPropertyCookieInformation implements SsoCookieInformation {

    private String cookieName;
    private String cookieDomain;

    /**
     * Find the cookie
     * 
     * @param systemPropertyCookieName
     *            cannot be null
     * @param systemPropertyCookieDomain
     *            can be null, if not null system property must exist
     */
    public SystemPropertyCookieInformation(String systemPropertyCookieName, String systemPropertyCookieDomain) {

        Validate.notNull(systemPropertyCookieName, "Null systemPropertyCookieName");

        this.cookieName = System.getProperty(systemPropertyCookieName);

        Validate.notNull(cookieName, "No cookie name found in system property: " + systemPropertyCookieName);

        if (null != systemPropertyCookieDomain) {
            this.cookieDomain = System.getProperty(systemPropertyCookieDomain);
            Validate.notNull(cookieDomain, "System property name for domain exists: %s but no property is defined.",
                    systemPropertyCookieDomain);
        }
    }

    @Override
    public String name() {
        return cookieName;
    }

    @Override
    public String domain() {
        return cookieDomain;
    }

}
