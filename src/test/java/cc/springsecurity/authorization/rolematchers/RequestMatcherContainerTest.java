package cc.springsecurity.authorization.rolematchers;

import org.junit.Test;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import junit.framework.Assert;

public class RequestMatcherContainerTest {

    @Test
    public void testContainers() {
        RequestMatcherContainer rmc = new RequestMatcherContainer();

        rmc.antPatterns("/**");
        rmc.regexPatterns("/[^/]+/.*");
        rmc.requestMatcher(new IpAddressMatcher("127.0.0.1"));

        Assert.assertEquals(3, rmc.getList().size());

    }
}
