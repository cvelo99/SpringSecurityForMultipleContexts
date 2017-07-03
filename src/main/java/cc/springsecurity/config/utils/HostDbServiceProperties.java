package cc.springsecurity.config.utils;

import javax.servlet.ServletContext;

public interface HostDbServiceProperties {

    /**
     * One of two preferred methods. Uses {@link HostNameUtils#getVirtualHostName()} to get the virtual host name.
     * 
     * @see #getServiceForHost(String, ServletContext)
     * @return
     */
    String getServiceForHost();

    /**
     * One of two preferred methods. See {@link #getServiceForHost(String, ServletContext)}
     * 
     * @param host
     * @return
     */
    String getServiceForHost(String host);

    /**
     * Return the service name for the given host and/or servlet context.
     * 
     * @param host
     *            the virual host, cannot be null.
     * @param context
     *            can be null, see method comments.
     * @return
     */
    String getServiceForHost(String host, ServletContext context);

}
