package cc.springsecurity.config.utils;

import javax.servlet.http.HttpServletRequest;

import cc.springsecurity.authentication.HostServletContext;

/**
 * Store the {@link HostContext} as a thread local for static access anywhere downstream.
 * 
 * @author Chris Carcel
 * 
 */
public final class HostName {

    private static final ThreadLocal<HostServletContext> HOST_CONTEXT = new ThreadLocal<>();

    /**
     * Hidden.
     */
    private HostName() {

    }

    /**
     * Sets the host name extracting it from the {@link HttpServletRequest}.
     * 
     * @param request
     * 
     */
    public static void setHostName(HttpServletRequest request) {
        HOST_CONTEXT.set(new HostServletContext(request.getServerName(), request.getContextPath()));
    }

    /**
     * Remove the current thread local host name.
     */
    public static void clearHostName() {
        HOST_CONTEXT.set(null);
    }

    /**
     * Gets the host name set in {@link #setHostName(HttpServletRequest)} throwing a {@link HostNameNotSetException} if it has not been set.
     * 
     * @return {@link HostContext}
     * @throws HostNameNotSetException
     *             if the host name as not been set
     */
    public static HostServletContext getHost() {
        HostServletContext result = HOST_CONTEXT.get();
        if (result == null) {
            throw new HostNameNotSetException("Thread-local HostContext not initialized.");
        }
        return result;
    }

}
