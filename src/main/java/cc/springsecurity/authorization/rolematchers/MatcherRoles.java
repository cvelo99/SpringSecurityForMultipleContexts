package cc.springsecurity.authorization.rolematchers;

import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Says that a certain set of {@link #roles()} is allowed to make the requests defined by the {@link RequestMatcher} .
 * 
 * @author Chris Carcel
 *
 */
public interface MatcherRoles {

    public RequestMatcher matcher();

    public String[] roles();

}
