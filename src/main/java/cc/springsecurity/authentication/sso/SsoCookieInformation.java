package cc.springsecurity.authentication.sso;

import javax.servlet.http.Cookie;

/**
 * Information we need to create the SSO cookie. This is the cookie we use to know we are logged into multiple applications.
 * 
 * @author Chris Carcel
 *
 */
public interface SsoCookieInformation {

    /**
     * The cookie name.
     * 
     * @return the cookie name
     */
    String name();

    /**
     * Optional cookie domain
     * 
     * @return can be null, if not the result is used in {@link Cookie#setDomain(String)}
     */
    String domain();

}
