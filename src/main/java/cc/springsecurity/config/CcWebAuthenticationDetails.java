package cc.springsecurity.config;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Created by {@link CcWebAuthenticationDetailsSource} , this class extends {@link WebAuthenticationDetails} to provide access to the
 * entire request. Used on login, this way we can determine which host we are under.
 * 
 * @see CcWebAuthenticationDetailsSource
 * @author Chris Carcel
 *
 */
@SuppressWarnings("serial")
public class CcWebAuthenticationDetails extends WebAuthenticationDetails {

    private HttpServletRequest request;

    public CcWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.request = request;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

}
