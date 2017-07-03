package cc.springsecurity.config.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/**
 * Obtains {@link HostDbServiceProperties} from a properties file.
 * 
 * @author carcelc
 * 
 */
@Component
@Lazy(value = true)
public final class HostDbServicePropertiesFile implements HostDbServiceProperties {

    private static final String HOST_SERVICE_PROPS_PATH = "PATH";

    private Map<String, String> hostServiceMap;

    private HostDbServicePropertiesFile() {

    }

    @PostConstruct
    private void setup() {

        File file = new File(HOST_SERVICE_PROPS_PATH);
        if (!file.exists() || !file.canRead()) {
            throw new IllegalStateException("Cannot read file " + HOST_SERVICE_PROPS_PATH);
        }

        Properties p = new Properties();
        FileInputStream fis = null;
        InputStreamReader isr = null;
        try {
            try {
                fis = new FileInputStream(file);
                isr = new InputStreamReader(fis, "UTF-8");
                p.load(isr);
            } finally {
                try {
                    isr.close();
                } catch (Throwable ignore) {
                    // ignore
                }
                try {
                    fis.close();
                } catch (Throwable ignore) {
                    // ignore
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Error Loading Host Service Map from File " + HOST_SERVICE_PROPS_PATH, e);
        }

        Map<String, String> hostServiceMap = new HashMap<String, String>(p.size());

        for (Map.Entry<Object, Object> entry : p.entrySet()) {
            hostServiceMap.put(entry.getKey().toString(), entry.getValue().toString());
        }

        this.hostServiceMap = Collections.unmodifiableMap(hostServiceMap);

    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.springsecurity.config.utils.HostDbServiceProperties#getServiceForHost()
     */
    @Override
    public String getServiceForHost() {
        return getServiceForHost(HostName.getHost().getHost(), null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.springsecurity.config.utils.HostDbServiceProperties#getServiceForHost(java.lang.String)
     */
    @Override
    public String getServiceForHost(String host) {
        return getServiceForHost(host, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.springsecurity.config.utils.HostDbServiceProperties#getServiceForHost(java.lang.String, javax.servlet.ServletContext)
     */
    @Override
    public String getServiceForHost(String host, ServletContext context) {

        if (null == host || "".equals(host)) {
            throw new IllegalStateException("Null Host");
        }

        String result = null;

        if (null != context) {
            StringBuilder key = new StringBuilder();
            key.append("Cc.Host.");
            key.append(host);
            key.append(".DbService");

            Object oService = context.getAttribute(key.toString());
            if (null != oService) {
                String s = oService.toString();
                if (this.hostServiceMap.containsValue(s)) {
                    // we have a valid service, return it
                    result = s;
                } else {
                    // we have specified a value that does not exist
                    throw new IllegalStateException(
                            "Service defined in context root under key " + key + " does not exist in file " + HOST_SERVICE_PROPS_PATH);
                }
            }

        }

        if (null == result) {

            if (null == context) {
                String service = this.hostServiceMap.get(host);
                if (null == service) {
                    throw new IllegalStateException("No Service Defined for host " + host + " in file " + HOST_SERVICE_PROPS_PATH);
                }
                result = service;

            }

        }

        if (null == result) {
            throw new IllegalStateException("No db service known for host " + host + ". This host is not defined in the file "
                    + HOST_SERVICE_PROPS_PATH + " nor is there a context parameter to map it");
        }

        return result;

    }

    /**
     * </ul>
     * 
     * @return
     */
    public Map<String, String> readOnlyViewOfHostDbProperties() {
        return this.hostServiceMap;
    }

}
