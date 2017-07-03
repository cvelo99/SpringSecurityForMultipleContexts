package cc.springsecurity.config.utils;

/**
 * Thrown when we attempt to access {@link HostName#getHost()} before setting the host.
 * 
 * @author Chris Carcel
 *
 */
@SuppressWarnings("serial")
public class HostNameNotSetException extends RuntimeException {

    public HostNameNotSetException() {
        super();
    }

    public HostNameNotSetException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public HostNameNotSetException(String message, Throwable cause) {
        super(message, cause);
    }

    public HostNameNotSetException(String message) {
        super(message);
    }

    public HostNameNotSetException(Throwable cause) {
        super(cause);
    }

}
