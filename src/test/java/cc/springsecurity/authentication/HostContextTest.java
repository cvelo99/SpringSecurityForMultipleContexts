package cc.springsecurity.authentication;

import org.junit.Test;

import junit.framework.Assert;

/**
 * Host context tests.
 * 
 * @author Chris Carcel
 *
 */
public class HostContextTest {

    @Test(expected = NullPointerException.class)
    public void noContextNpeTest() {
        new HostServletContext("192.168.0.0.1", null);
    }

    @Test
    public void ipAddressTest() {
        HostServletContext hc = new HostServletContext("192.168.0.1", "/fred");
        Assert.assertNull(hc.getHost());
    }

    @Test
    public void testDomain() {
        HostServletContext hc = new HostServletContext("zendesk.com", "/fred");
        Assert.assertTrue("zendesk.com".equals(hc.getHost()));
        Assert.assertTrue("/fred".equals(hc.getContext()));
    }

    @Test
    public void testDomainWithSub() {
        HostServletContext hc = new HostServletContext("bob.zendesk.com", "/fred");
        Assert.assertTrue("bob.zendesk.com".equals(hc.getHost()));
        Assert.assertTrue("/fred".equals(hc.getContext()));
    }

    @Test
    public void localHostTest() {
        HostServletContext hc = new HostServletContext("localhost", "/fred");
        Assert.assertTrue("localhost".equals(hc.getHost()));
        Assert.assertTrue("/fred".equals(hc.getContext()));
    }

}
