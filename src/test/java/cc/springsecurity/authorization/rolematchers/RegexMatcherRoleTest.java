package cc.springsecurity.authorization.rolematchers;

import org.junit.Test;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import junit.framework.Assert;

public class RegexMatcherRoleTest {

    @Test
    public void test1() {
        MatcherRolesContainer mrc = new MatcherRolesContainer();
        mrc.regexPatterns("/[^/]+/.*", "TestRole2");
        RequestMatcher matcher = mrc.getRoles().iterator().next().matcher();
        Assert.assertTrue(matcher instanceof RegexRequestMatcher);
    }

}
