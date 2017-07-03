package cc.springsecurity.authorization.rolematchers;

import org.junit.Test;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import junit.framework.Assert;

public class AntMatcherRoleTest {

    @Test
    public void test1() {
        MatcherRolesContainer mrc = new MatcherRolesContainer();
        mrc.antPath("/**", "TestRole1");
        RequestMatcher matcher = mrc.getRoles().iterator().next().matcher();
        Assert.assertTrue(matcher instanceof AntPathRequestMatcher);
    }

}
