package cc.springsecurity.authorization.rolematchers;

import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Holder for Regex {@link RequestMatcher} roles. Typically accessed via {@link MatcherRolesContainer}
 * 
 * @see AntMatcherRole
 * @see RequestMatcherRole
 * @author Chris Carcel
 *
 */
public class RegexMatcherRole implements MatcherRoles {

    private RequestMatcher regexMatcher;

    private String[] roles;

    RegexMatcherRole(String path, String... roles) {
        this.regexMatcher = new RegexRequestMatcher(path, null);
        this.roles = roles;
    }

    @Override
    public RequestMatcher matcher() {
        return regexMatcher;
    }

    @Override
    public String[] roles() {
        return roles;
    }

}
