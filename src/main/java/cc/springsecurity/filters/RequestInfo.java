package cc.springsecurity.filters;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import cc.springsecurity.config.utils.HostName;

/**
 * Should be the first filter in the spring security filter chain. Calls the {@link HostName#setHostName(HttpServletRequest)} to set the
 * host name making it accessible via a static method call in any code downstream. It also sets a request attribute,
 * {@link RequestInfo#UUID_ATTRIBUTE} as a unique identifier for this request for logging purposes.
 * 
 * @author Chris Carcel
 *
 */
public class RequestInfo implements Filter {

    private static final String UUID_ATTRIBUTE = "cc.springsecurity.filters.RequestInfo.UUID";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest req = (HttpServletRequest) request;
            req.setAttribute(RequestInfo.UUID_ATTRIBUTE, UUID.randomUUID().toString());
            HostName.setHostName(req);
            try {
                chain.doFilter(request, response);
            } finally {
                HostName.clearHostName();
                req.removeAttribute(UUID_ATTRIBUTE);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

    @Override
    public void destroy() {

    }

}
