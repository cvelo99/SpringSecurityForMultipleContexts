package cc.springsecurity.authentication.providers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.Validate;

import cc.springsecurity.authentication.AbstractCcUserDetailsAuthenticationProvider;
import cc.springsecurity.authentication.hash.PasswordHashing;
import cc.springsecurity.config.CcPrincipal;
import cc.springsecurity.config.CcPrincipalImpl;
import cc.springsecurity.config.CcWebAuthenticationDetails;

/**
 * Hard coded user name, password, roles/groups list. Useful for testing or prototyping. Sample code: <br>
 * <br>
 * 
 * <pre>
 * <code>  
 * UsernamePasswordGroupsList build = HardCodedAuthenticationProvider.UsernamePasswordGroupsBuilder.getInstance() 
 * 	.createUser(1, "FirstName", "LastName", "email_address@email.com", "hashed_pw", Sets.newHashSet("Admins"))
 *   .build();
 *   
 * HardCodedAuthenticationProvider auth = new HardCodedAuthenticationProvider(build);
 * </code>
 * </pre>
 * 
 * 
 * @author Chris Carcel
 *
 */
public class HardCodedAuthenticationProvider extends AbstractCcUserDetailsAuthenticationProvider {

    private UsernamePasswordGroupsList list;

    private static class UserNamePasswordGroups {

        private final Integer userId;
        private final String firstName;
        private final String lastName;
        private final String email;
        private final String password;
        private final Set<String> groups;

        public UserNamePasswordGroups(Integer userId, String firstName, String lastName, String email, String password,
                Set<String> groups) {
            super();
            this.userId = userId;
            this.firstName = firstName;
            this.lastName = lastName;
            this.email = email;
            this.password = password;
            this.groups = groups;
        }

    }

    public static class UsernamePasswordGroupsList {

        private List<UserNamePasswordGroups> list;

        private UsernamePasswordGroupsList() {
            this.list = new ArrayList<>();
        }

        private void addUser(UserNamePasswordGroups upg) {
            // make sure the user id and email are unique
            Validate.isTrue(0L == list.stream().filter(l -> l.userId.equals(upg.userId)).count(), "User ID %d is already defined.",
                    upg.userId);
            Validate.isTrue(0L == list.stream().filter(l -> l.email.equals(upg.email)).count(), "Email %s is already defined.", upg.email);
            list.add(upg);
        }

        private List<UserNamePasswordGroups> getList() {
            return this.list;
        }

    }

    /**
     * Creates a list of users for a hard coded authentication scheme, useful for testing and small betas.
     * 
     * @author Chris Carcel
     *
     */
    public static class UsernamePasswordGroupsBuilder {

        private UsernamePasswordGroupsList list;

        public static UsernamePasswordGroupsBuilder getInstance() {
            return new UsernamePasswordGroupsBuilder();
        }

        private UsernamePasswordGroupsBuilder() {
            this.list = new UsernamePasswordGroupsList();
        }

        /**
         * Create a user. Note the password should be hashed using {@link PasswordHashing#buildPasswordHash(String)}
         * 
         * @param userId
         *            unique user identifier
         * @param firstName
         *            first name
         * @param lastName
         *            last name
         * @param email
         *            email address, must also be unique
         * @param password
         *            the hashed password using {@link PasswordHashing#buildPasswordHash(String)}
         * @param groups
         *            set groups to which this user belongs, can be null
         * @return
         */
        public UsernamePasswordGroupsBuilder createUser(Integer userId, String firstName, String lastName, String email, String password,
                Set<String> groups) {
            Validate.noNullElements(Stream.of(userId, firstName, lastName, email, password).collect(Collectors.toList()),
                    "userId, first name, last name, email and password cannot be null");
            groups = null == groups ? Collections.emptySet() : Collections.unmodifiableSet(groups);
            UserNamePasswordGroups g = new UserNamePasswordGroups(userId, firstName, lastName, email, password, groups);
            list.addUser(g);
            return this;
        }

        public UsernamePasswordGroupsList build() {
            return list;
        }
    }

    /**
     * Setup, pass in user list using code like so: <br>
     * <br>
     * <code>
     * UsernamePasswordGroupsList build = HardCodedAuthenticationProvider.UsernamePasswordGroupsBuilder.getInstance()
    			.createUser(1, "FirstName", "LastName", "Email@email.com", "hashed_pw", Sets.newHashSet("GroupName")).build();</code>
     * 
     * @param list
     * @see HardCodedAuthenticationProvider
     * @see PasswordHashing#buildPasswordHash(String)
     */
    public HardCodedAuthenticationProvider(UsernamePasswordGroupsList list) {
        this.list = list;
    }

    @Override
    protected CcPrincipal validateUser(String username, String password, CcWebAuthenticationDetails details) {
        PasswordHashing ph = new PasswordHashing();
        for (UserNamePasswordGroups upg : this.list.getList()) {
            if (upg.email.equals(username) && ph.verifyPassword(upg.password, password)) {
                CcPrincipalImpl ccp = new CcPrincipalImpl();
                ccp.setEmail(upg.email);
                ccp.setFirstName(upg.firstName);
                ccp.setLastName(upg.lastName);
                ccp.setUserId(upg.userId);
                ccp.setUsername(upg.firstName.concat(" ").concat(upg.lastName));
                ccp.setGroups(upg.groups.toArray(new String[upg.groups.size()]));
                return ccp;
            }
        }
        return null;
    }
}
