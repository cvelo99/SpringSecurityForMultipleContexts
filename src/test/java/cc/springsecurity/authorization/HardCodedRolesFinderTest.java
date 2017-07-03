package cc.springsecurity.authorization;

import static java.util.stream.Collectors.toCollection;
import static java.util.stream.Collectors.toSet;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.Test;

import cc.springsecurity.authentication.HostServletContext;
import junit.framework.Assert;

/**
 * Test {@link AbstractHardCodedRolesFinder}
 * 
 * @author TeamBeaker
 *
 */
public class HardCodedRolesFinderTest {

    /**
     * Internal class which provides concrete implementation of {@link AbstractHardCodedRolesFinder} .
     * 
     * @author Chris Carcel
     *
     */
    class TestRolesFinder extends AbstractHardCodedRolesFinder {

        @Override
        protected Map<HostServletContext, Map<String, Set<String>>> getRoleGroupMap() {

            Map<HostServletContext, Map<String, Set<String>>> result = new LinkedHashMap<>();

            Map<String, Set<String>> roleToGroups1 = new HashMap<>();
            roleToGroups1.put("ROLE1", Stream.of("A", "B").collect(toCollection(HashSet::new)));
            result.put(new HostServletContext(null, "/bob"), roleToGroups1);

            Map<String, Set<String>> roleToGroups2 = new HashMap<>();
            roleToGroups2.put("ROLE2", Stream.of("A", "B").collect(toCollection(HashSet::new)));
            roleToGroups2.put("ROLE3", Stream.of("C").collect(toCollection(HashSet::new)));
            result.put(new HostServletContext("fred", "/bob"), roleToGroups2);

            return result;
        }

    }

    private TestRolesFinder roles;

    @Before
    public void before() {

        this.roles = new TestRolesFinder();

    }

    @Test
    public void testMap1() {
        Map<String, Set<String>> map = roles.getRoleGroupMap().get(new HostServletContext(null, "/bob"));
        Assert.assertEquals(1, map.size());
    }

    @Test
    public void testMap2() {
        Map<String, Set<String>> map = roles.getRoleGroupMap().get(new HostServletContext("fred", "/bob"));
        Assert.assertEquals(2, map.size());
    }

    @Test
    public void testNada() {
        Map<String, Set<String>> map = roles.getRoleGroupMap().get(new HostServletContext(null, "/bober"));
        Assert.assertNull(map);
    }

}
