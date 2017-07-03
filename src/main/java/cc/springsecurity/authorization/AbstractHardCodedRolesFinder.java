package cc.springsecurity.authorization;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import cc.springsecurity.authentication.HostServletContext;

/**
 * Abstract base class for hard coded roles and groups.
 * 
 * @author Chris Carcel
 *
 */
public abstract class AbstractHardCodedRolesFinder implements RolesFinder {

    /**
     * Return the hard-coded map. In the Map&lt;String, Set&lt;String&gt;&gt; the key is a role name (minus the ROLE) and the value is a set
     * of groups which have that role.
     * 
     * @return
     */
    protected abstract Map<HostServletContext, Map<String, Set<String>>> getRoleGroupMap();

    @Override
    public Set<String> roles(HostServletContext hostServletContext, String[] groups) {

        if (null == groups || groups.length == 0) {
            return Collections.emptySet();
        }

        Map<String, Set<String>> roleGroups = getRoleGroupMap().get(hostServletContext);

        if (null == roleGroups) {
            return Collections.emptySet();
        }

        Set<String> userRoles = new HashSet<>();

        for (Map.Entry<String, Set<String>> entry : roleGroups.entrySet()) {
            for (String group : groups) {
                if (entry.getValue().contains(group)) {
                    userRoles.add(entry.getKey());
                    break;
                }
            }

        }

        return userRoles;
    }
}
