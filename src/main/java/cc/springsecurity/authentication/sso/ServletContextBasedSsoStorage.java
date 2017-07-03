package cc.springsecurity.authentication.sso;

import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.ServletContext;

import org.apache.commons.lang3.Validate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import cc.springsecurity.config.CcPrincipal;

/**
 * Servlet context based sso storage. Not really SSO at all, but usable for securing a single war.
 * 
 * @author Chris Carcel
 *
 */
public class ServletContextBasedSsoStorage implements SsoStorage {

    private static final String CONTEXT_ATTRIBUTE_NAME = ServletContextBasedSsoStorage.class.getName();

    private ConcurrentHashMap<String, Object> map;

    @SuppressWarnings("unchecked")
    public ServletContextBasedSsoStorage(ServletContext ctx) {
        Validate.notNull(ctx, "ServletContext is null");
        Object contextMap = ctx.getAttribute(CONTEXT_ATTRIBUTE_NAME);
        if (null == contextMap) {
            map = new ConcurrentHashMap<String, Object>();
            ctx.setAttribute(CONTEXT_ATTRIBUTE_NAME, map);
        } else {
            map = (ConcurrentHashMap<String, Object>) contextMap;
        }
    }

    @Override
    public UserDetails findUser(String unid) {
        return (CcPrincipal) map.get(unid);
    }

    @Override
    public void storeUser(String unid, Authentication auth) {
        if (auth.isAuthenticated()) {
            map.put(unid, auth.getPrincipal());
        }
    }

    @Override
    public void removeUser(String unid) {
        map.remove(unid);
    }

}
