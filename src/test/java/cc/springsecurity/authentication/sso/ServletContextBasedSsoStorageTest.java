package cc.springsecurity.authentication.sso;

import static java.util.stream.Collectors.toSet;

import java.util.Set;
import java.util.stream.Stream;

import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import cc.springsecurity.config.CcPrincipalImpl;
import junit.framework.Assert;

/**
 * Test servlet context based Sso storage.
 * 
 * @author Chris Carcel
 *
 */
public class ServletContextBasedSsoStorageTest {

    @Test(expected = NullPointerException.class)
    public void testMissingServletContext() {
        new ServletContextBasedSsoStorage(null);
    }

    @Test
    public void testSetup() {
        new ServletContextBasedSsoStorage(new MockServletContext());
    }

    @Test
    public void testCannotAddUser() {
        ServletContextBasedSsoStorage ss = new ServletContextBasedSsoStorage(new MockServletContext());
        ss.storeUser("unid", new UsernamePasswordAuthenticationToken(new Object(), new Object())); // not authenticated
        UserDetails findUser = ss.findUser("unid");
        Assert.assertNull(findUser);
    }

    @Test(expected = ClassCastException.class)
    public void testAddUserFails() {
        ServletContextBasedSsoStorage ss = new ServletContextBasedSsoStorage(new MockServletContext());
        Set<SimpleGrantedAuthority> set = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        ss.storeUser("unid", new UsernamePasswordAuthenticationToken(new Object(), new Object(), set));
        UserDetails findUser = ss.findUser("unid");
        Assert.assertNotNull(findUser);
    }

    @Test
    public void testAddUser() {
        ServletContextBasedSsoStorage ss = new ServletContextBasedSsoStorage(new MockServletContext());
        Set<SimpleGrantedAuthority> set = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        ss.storeUser("unid", new UsernamePasswordAuthenticationToken(new CcPrincipalImpl(), new Object(), set));
        UserDetails findUser = ss.findUser("unid");
        Assert.assertNotNull(findUser);
    }

}
