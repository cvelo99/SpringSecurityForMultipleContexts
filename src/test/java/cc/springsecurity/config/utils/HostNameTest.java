package cc.springsecurity.config.utils;

import java.lang.reflect.InvocationTargetException;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import cc.springsecurity.authentication.HostServletContext;
import junit.framework.Assert;

public class HostNameTest {

    @Test
    public void testHostNameExtraction()
            throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {

        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setServerName("test.com");
        req.setMethod("GET");
        req.setRequestURI("/test/test");
        req.setContextPath("/test");
        HostName.setHostName(req);

        HostServletContext hostContext = HostName.getHost();

        Assert.assertTrue(null != hostContext);
        Assert.assertTrue("test.com".equals(hostContext.getHost()));
        Assert.assertTrue("/test".equals(hostContext.getContext()));

    }

    @Test(expected = HostNameNotSetException.class)
    public void testNoHostSet() {

        HostName.getHost();

    }
}
