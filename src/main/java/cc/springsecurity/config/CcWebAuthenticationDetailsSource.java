package cc.springsecurity.config;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

/**
 * Extends {@link WebAuthenticationDetailsSource} to return a {@link CcWebAuthenticationDetails} to give us access to the entire request on
 * login.
 * 
 * @author Chris Carcel
 *
 */
@Component
public class CcWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource {

    @Override
    public CcWebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new CcWebAuthenticationDetails(request);
    }

}
