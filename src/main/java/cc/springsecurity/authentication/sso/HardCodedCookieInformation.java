package cc.springsecurity.authentication.sso;

import org.apache.commons.lang3.Validate;

/**
 * Hard code the cookie name and domain.
 * 
 * @author Chris Carcel
 *
 */
public class HardCodedCookieInformation implements SsoCookieInformation {

    private final String cookieName;
    private final String cookieDomain;

    /**
     * Find the cookie
     * 
     * @param cookieName
     *            cannot be null
     * @param cookieDomain
     *            can be null
     */
    public HardCodedCookieInformation(String cookieName, String cookieDomain) {

        Validate.notNull(cookieName, "Null cookieName");

        this.cookieName = cookieName;

        this.cookieDomain = cookieDomain;
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
