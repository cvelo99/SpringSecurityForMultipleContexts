package cc.springsecurity.authorization.rolematchers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Facilitates the creation and storing of multiple {@link RequestMatcher}'s .
 * 
 * @author Chris Carcel
 *
 */
public class RequestMatcherContainer {

    private List<RequestMatcher> list;

    public RequestMatcherContainer() {
        this.list = new ArrayList<RequestMatcher>();
    }

    /**
     * Add any {@link RequestMatcher} you'd like. Prefer the other two methods {@link #antPatterns(String...)} or
     * {@link #regexPatterns(String...)} to this. Keep in mind if specifying IP addresses it is best to specify both IPV4 and IPV6
     * addresses.
     * 
     * @param matchers
     * @return
     */
    public RequestMatcherContainer requestMatcher(RequestMatcher... matchers) {
        for (RequestMatcher matcher : matchers) {
            this.list.add(matcher);
        }
        return this;
    }

    /**
     * Add the ant patterns, for example<br>
     * <code>"/css/**", "/fonts/**", "/js/**"</code></br>
     * 
     * @see http://docs.spring.io/spring-security/site/docs/current/apidocs/index.html?org/springframework/security/web/util/matcher/
     *      AntPathRequestMatcher.html
     * 
     * @param patterns
     * @return this object
     */
    public RequestMatcherContainer antPatterns(String... patterns) {
        for (String s : patterns) {
            list.add(new AntPathRequestMatcher(s));
        }
        return this;
    }

    /**
     * Add regex patterns.
     * 
     * @see http://docs.spring.io/autorepo/docs/spring-security/current/apidocs/org/springframework/security/web/util/matcher/
     *      RegexRequestMatcher.html
     * @param patterns
     * @return this object
     */
    public RequestMatcherContainer regexPatterns(String... patterns) {
        for (String s : patterns) {
            list.add(new RegexRequestMatcher(s, null));
        }
        return this;
    }

    public List<RequestMatcher> getList() {
        return Collections.unmodifiableList(list);
    }

}
