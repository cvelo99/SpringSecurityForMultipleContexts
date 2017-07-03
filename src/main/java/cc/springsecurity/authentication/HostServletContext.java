package cc.springsecurity.authentication;

import org.apache.commons.validator.routines.InetAddressValidator;

public class HostServletContext {

    private String host;
    private String context;

    public HostServletContext(String host, String context) {
        if (null == host || "localhost".equals(host) || InetAddressValidator.getInstance().isValid(host)) {
            this.host = null;
        } else {
            this.host = host;
        }
        this.context = context;
    }

    public String getHost() {
        return host;
    }

    public String getContext() {
        return context;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (prime * result) + ((context == null) ? 0 : context.hashCode());
        result = (prime * result) + ((host == null) ? 0 : host.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        HostServletContext other = (HostServletContext) obj;
        if (context == null) {
            if (other.context != null) {
                return false;
            }
        } else if (!context.equals(other.context)) {
            return false;
        }
        if (host == null) {
            if (other.host != null) {
                return false;
            }
        } else if (!host.equals(other.host)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "HostServletContext [host=" + host + ", context=" + context + "]";
    }

}
