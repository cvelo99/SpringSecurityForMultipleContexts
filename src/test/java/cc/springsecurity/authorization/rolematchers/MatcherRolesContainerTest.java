package cc.springsecurity.authorization.rolematchers;

import org.junit.Test;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import junit.framework.Assert;

public class MatcherRolesContainerTest {

    @Test
    public void testContainers() {
        MatcherRolesContainer mrc = new MatcherRolesContainer();

        mrc.antPath("/**", "TestRole1");
        mrc.regexPatterns("/[^/]+/.*", "TestRole2");
        mrc.requestMatchers(new IpAddressMatcher("127.0.0.1"), "TestRole3");

        Assert.assertEquals(3, mrc.getRoles().size());

    }

}
