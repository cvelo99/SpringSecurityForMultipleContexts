package cc.springsecurity.authentication.sso;

import static java.util.stream.Collectors.toSet;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Stream;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import cc.springsecurity.config.CcPrincipalImpl;

public class SsoAuthenticatedFilterTest {

    @Test
    public void testNoCookieButAppearsToBeLoggedIn() throws IOException, ServletException {

        SsoAuthenticatedFilter filter = new SsoAuthenticatedFilter();

        filter.setCookieInformation(null);
        filter.setSsoStorage(new FileBasedSsoStorage());

        Set<SimpleGrantedAuthority> creds = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(new CcPrincipalImpl(), new Object(), creds));

        String contextPath = "/bob";

        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setContextPath(contextPath);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);

        Assert.assertTrue(res.isCommitted());
        Assert.assertEquals(res.getHeader("Location"), contextPath);
        Assert.assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, res.getStatus());

    }

    @Test
    public void testHasCookieButNotLoggedIn() throws IOException, ServletException {

        // TODO finish

        SsoAuthenticatedFilter filter = new SsoAuthenticatedFilter();

        String cookieName = "cn";

        HardCodedCookieInformation cif = new HardCodedCookieInformation(cookieName, null);

        filter.setCookieInformation(cif);
        filter.setSsoStorage(new FileBasedSsoStorage());

        Set<SimpleGrantedAuthority> creds = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());

        String contextPath = "/bob";

        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setCookies(new Cookie(cookieName, "cv"));

        req.setContextPath(contextPath);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);

        Assert.assertTrue(res.isCommitted());
        Assert.assertEquals(res.getHeader("Location"), contextPath);
        Assert.assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, res.getStatus());

    }

    /**
     * In other words, the user is logged in and all is well.
     * 
     * @throws IOException
     * @throws ServletException
     */
    @Test
    public void testHasCookieAndLoggedIn() throws IOException, ServletException {

        SsoAuthenticatedFilter filter = new SsoAuthenticatedFilter();

        HardCodedCookieInformation cif = new HardCodedCookieInformation("cn", "testing");

        filter.setCookieInformation(cif);
        FileBasedSsoStorage ssoStorage = new FileBasedSsoStorage();

        Set<SimpleGrantedAuthority> creds = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(new CcPrincipalImpl(), new Object(), creds);
        ssoStorage.storeUser("cv", token);

        filter.setSsoStorage(ssoStorage);

        SecurityContextHolder.getContext().setAuthentication(token);

        String contextPath = "/bob";

        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setCookies(new Cookie("cn", "cv"));

        class MyMockFilter implements Filter {

            private boolean doFilterCalled;

            @Override
            public void init(FilterConfig filterConfig) throws ServletException {
            }

            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                this.doFilterCalled = true;
            }

            public boolean isDoFilterCalled() {
                return doFilterCalled;
            }

            @Override
            public void destroy() {
            }

        }

        @SuppressWarnings("serial")
        class MyServlet extends GenericServlet {

            @Override
            public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            }

        }

        req.setContextPath(contextPath);
        MockHttpServletResponse res = new MockHttpServletResponse();

        MyMockFilter mmf = new MyMockFilter();
        MockFilterChain chain = new MockFilterChain(new MyServlet(), mmf);

        filter.doFilter(req, res, chain);

        Assert.assertTrue(mmf.isDoFilterCalled());

    }

}
