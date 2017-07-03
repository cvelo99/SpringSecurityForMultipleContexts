package cc.springsecurity.authorization.rolematchers;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Holder for ant matchers and roles. Typically accessed via {@link MatcherRolesContainer}
 * 
 * @see RegexMatcherRole
 * @see RegexMatcherRole
 * @author Chris Carcel
 *
 */
public class AntMatcherRole implements MatcherRoles {

    private AntPathRequestMatcher antMatcher;

    private String[] roles;

    AntMatcherRole(String path, String... roles) {
        this.antMatcher = new AntPathRequestMatcher(path);
        this.roles = roles;
    }

    @Override
    public RequestMatcher matcher() {
        return antMatcher;
    }

    @Override
    public String[] roles() {
        return roles;
    }

}
