package cc.springsecurity.authorization.rolematchers;

import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Holding for a generic {@link RequestMatcher} and a role. Typically accessed via {@link MatcherRolesContainer}
 * 
 * @see RegexMatcherRole
 * @see AntMatcherRole
 * @author Chris Carcel
 *
 */
public class RequestMatcherRole implements MatcherRoles {

    private RequestMatcher matcher;

    private String[] roles;

    RequestMatcherRole(RequestMatcher matcher, String... roles) {
        this.matcher = matcher;
        this.roles = roles;
    }

    @Override
    public RequestMatcher matcher() {
        return matcher;
    }

    @Override
    public String[] roles() {
        return roles;
    }

}
