package cc.springsecurity.authorization.rolematchers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Holds {@link MatcherRoles} which connect {@link RequestMatcher} 's to roles.
 * 
 * @author Chris Carcel
 *
 */
public class MatcherRolesContainer {

    private List<MatcherRoles> list;

    public MatcherRolesContainer() {
        this.list = new ArrayList<>();
    }

    /**
     * Add ant paths.
     * 
     * @param antPattern
     *            ant paths to secure
     * @param roles
     *            roles which can access this path
     * @return this object
     */
    public MatcherRolesContainer antPath(String antPattern, String... roles) {
        list.add(new AntMatcherRole(antPattern, roles));
        return this;
    }

    /**
     * Add regex patterns.
     * 
     * @see http://docs.spring.io/autorepo/docs/spring-security/current/apidocs/org/springframework/security/web/util/matcher/
     *      RegexRequestMatcher.html
     * @param patterns
     * @param the
     *            roles which can access this path
     * @return this object
     */
    public MatcherRolesContainer regexPatterns(String s, String... roles) {
        list.add(new RegexMatcherRole(s, roles));
        return this;
    }

    /**
     * Add a generic request matcher to the list.
     * 
     * @param rm
     *            any (Spring) {@link RequestMatcher}
     * @param roles
     *            the roles which can access it
     * @return this object
     */
    public MatcherRolesContainer requestMatchers(RequestMatcher rm, String... roles) {
        list.add(new RequestMatcherRole(rm, roles));
        return this;
    }

    public List<MatcherRoles> getRoles() {
        return Collections.unmodifiableList(list);
    }

}
