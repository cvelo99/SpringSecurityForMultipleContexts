package cc.springsecurity.authentication.sso;

import java.io.IOException;
import java.net.HttpCookie;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Handles SsoLogout, clearing cookies, redirecting users, removing from Sso storage.
 * 
 * @author carcelc
 *
 */
@Component
public class SsoLogoutSuccessHandler implements LogoutSuccessHandler {

    private SsoStorage ssoStorage;

    private SsoCookieInformation cookieInformation;

    private String logoutUrl;

    private Collection<HttpCookie> cookiesToRemove;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        String cookieValue = extractCookieValue(request);
        if (null != cookieValue) {
            ssoStorage.removeUser(cookieValue);
        }

        if (null != cookiesToRemove) {
            clearCookies(response);
        }

        response.sendRedirect(request.getContextPath() + logoutUrl);
    }

    private void clearCookies(HttpServletResponse response) {

        for (HttpCookie c : cookiesToRemove) {

            Cookie cookie = new Cookie(c.getName(), c.getDomain());
            cookie.setPath(c.getPath());
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
    }

    /**
     * Return the sso cookie value.
     * 
     * @param request
     * @return
     */
    private String extractCookieValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (null != cookies) {
            for (Cookie cookie : cookies) {
                if (cookieInformation.name().equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public void setSsoStorage(SsoStorage ssoStorage) {
        this.ssoStorage = ssoStorage;
    }

    public void setCookieInformation(SsoCookieInformation cookieInformation) {
        this.cookieInformation = cookieInformation;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    /**
     * Set a list of cookies to remove. Neither the list, nor the elements in it, will be modified.
     * 
     * @param cookiesToRemove
     */
    public void setCookiesToRemove(Collection<HttpCookie> cookiesToRemove) {
        this.cookiesToRemove = cookiesToRemove;
    }

}
