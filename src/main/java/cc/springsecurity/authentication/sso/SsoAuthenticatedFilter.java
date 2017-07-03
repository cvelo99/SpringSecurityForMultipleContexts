package cc.springsecurity.authentication.sso;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Filter to make sure we are still authenticated (i.e. still in sso storage) on each request. If necessary, we could consider extending
 * {@link org.springframework.web.filter.GenericFilterBean}
 * 
 * @author carcelc
 *
 */
@Component
public class SsoAuthenticatedFilter implements Filter {

    private SsoStorage ssoStorage;

    private SsoCookieInformation cookieInformation;

    @Override
    public void init(FilterConfig config) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        // see if this is an authenticated request
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (null != auth && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            // it is, make sure still logged in

            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            boolean stillAuthenticated = false;
            String cookie = extractCookie(request);
            if (null != cookie) {
                if (null != ssoStorage.findUser(cookie)) {
                    stillAuthenticated = true;
                }
            }

            if (!stillAuthenticated) {
                // clear auth context
                SecurityContextHolder.getContext().setAuthentication(null);
                // invalidate session
                HttpSession session = request.getSession(false);
                if (null != session) {
                    session.invalidate();
                }
                // redirect to home
                response.sendRedirect(request.getContextPath());
            } else {
                // authenticated, continue
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(req, res);
        }
    }

    private String extractCookie(HttpServletRequest request) {
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

    @Override
    public void destroy() {
    }

    public void setSsoStorage(SsoStorage ssoStorage) {
        this.ssoStorage = ssoStorage;
    }

    public void setCookieInformation(SsoCookieInformation cookieInformation) {
        this.cookieInformation = cookieInformation;
    }

}
