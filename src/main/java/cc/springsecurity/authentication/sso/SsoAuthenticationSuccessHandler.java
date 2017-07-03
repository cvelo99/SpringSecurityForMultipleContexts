package cc.springsecurity.authentication.sso;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.Validate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Authentication success handler. Extends the default {@link SavedRequestAwareAuthenticationSuccessHandler} to forward the user to the URL
 * they originally requested. Creates the {@link SsoCookieInformation} cookie and then uses {@link SsoStorage} to store the cookie value and
 * SSO / {@link Authentication} information.
 * 
 * @author Chris Carcel
 *
 */
@Component
public class SsoAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private SsoStorage ssoStorage;

    private SsoCookieInformation cookieInformation;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        Validate.isTrue(null != cookieInformation, "cookieInformation cannot be null, be sure to call setCookieInformation");

        String unid = unid();
        Cookie c = new Cookie(cookieInformation.name(), unid);
        if (null != cookieInformation.domain()) {
            c.setDomain(cookieInformation.domain());
        }
        c.setPath("/");
        response.addCookie(c);

        ssoStorage.storeUser(unid, authentication);

        // call super to redirect to the originally requested url
        super.onAuthenticationSuccess(request, response, authentication);

    }

    /**
     * Generate the UUID for the cookie value.
     * 
     * @return
     */
    private String unid() {
        return UUID.randomUUID().toString();
    }

    public void setCookieInformation(SsoCookieInformation cookieInformation) {
        this.cookieInformation = cookieInformation;
    }

    public void setSsoStorage(SsoStorage ssoStorage) {
        this.ssoStorage = ssoStorage;
    }

}
