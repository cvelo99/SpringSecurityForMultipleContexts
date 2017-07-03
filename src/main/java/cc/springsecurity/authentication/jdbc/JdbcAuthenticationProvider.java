package cc.springsecurity.authentication.jdbc;

import java.sql.Connection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.naming.NamingException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import cc.springsecurity.authentication.AbstractCcUserDetailsAuthenticationProvider;
import cc.springsecurity.authentication.hash.PasswordUtil;
import cc.springsecurity.authorization.RolesFinder;
import cc.springsecurity.config.CcPrincipal;
import cc.springsecurity.config.CcPrincipalImpl;
import cc.springsecurity.config.CcWebAuthenticationDetails;
import cc.springsecurity.config.utils.HostDbServiceProperties;

@Component
public class JdbcAuthenticationProvider extends AbstractCcUserDetailsAuthenticationProvider {

    @Autowired
    private PasswordUtil passwordUtil;

    private HostDbServiceProperties hostDbServiceProperties;

    private Logger log = LoggerFactory.getLogger(JdbcAuthenticationProvider.class);

    /**
     * The data source name, defaults to ds-admin.
     */
    private String dataSourceName = "ds-admin";

    @Override
    protected CcPrincipal validateUser(String username, String password, CcWebAuthenticationDetails details) {
        return validateUserOnJboss(username, password, details);
    }

    /**
     * Attempts to login a user to jboss.
     * 
     * @param username
     * @param password
     * @return
     */
    private CcPrincipal validateUserOnJboss(String username, String password, CcWebAuthenticationDetails wed) {

        CcPrincipalImpl result = null;

        boolean success = false;

        Integer userId = null;

        Connection connection = null;
        try {
            // validate
            DataSource ds = lookupDataSource(wed);
            JdbcTemplate t = new JdbcTemplate(ds);

            String query = "select id, user_id, password_hash, salt from passwords where lower(login_name) = lower(:un) and active = 1";
            List<Map<String, Object>> results = t.queryForList(query, username);
            if (results.isEmpty()) {
                // no match
                log.info("No Matching Jboss user found");
                success = false;
            } else if (results.size() > 1) {
                // more than 1 match, invalid
                log.warn(results.size() + " users found matching this user name, this is invalid");
                success = false;
            } else {
                Map<String, Object> map = results.iterator().next();
                // found match, validate password
                String passwordHash = (String) map.get("PASSWORD_HASH");
                String salt = (String) map.get("SALT");
                if (validateJbossPassword(password, passwordHash, salt)) {
                    success = true;
                    userId = ((Number) map.get("USER_ID")).intValue();
                } else {
                    success = false;
                }
            }

            // we have now validated the password

            if (success) {
                result = new CcPrincipalImpl();

                if (success) {
                    this.updatePrincipleData(username, result, userId, t, wed);
                }
            }

        } catch (Exception ex) {
            log.error("Error Validating User on Jboss", ex);
            success = false;
        } finally {
            JdbcUtils.closeConnection(connection);
        }

        return success ? result : null;
    }

    /**
     * Used for both login types. Stores the information from the session <b>or</b> from tables into the CcPrincipal.
     * 
     * @param userNameForLogin
     *            the user name they used to login
     * @param ccrincipal
     *            The CcPrincipal to store the data in
     * @param session
     *            The Notes Session containing the data. Can be null if this is a jboss login. If this not null, the <code>userId</code> and
     *            <code>t</code> are ignored.
     * @param userId
     *            the user id of the user. Specified when a jboss login occurs. If the <code>session</code> is not null, this is ignored. If
     *            session is null, it is assumed that this and <code>t</code> are not null
     * @param t
     *            template, used only on a jboss login, see <code>userId</code>comment
     * @param wed
     * @throws LoginException
     */
    private void updatePrincipleData(String userNameForLogin, final CcPrincipalImpl ccrincipal, Integer userId, JdbcTemplate t,
            CcWebAuthenticationDetails wed) {

        // set the user name they logged in with
        ccrincipal.setUsername(userNameForLogin);

        final Set<String> notesGroupList;

        // set the names
        String nameQuery = "select user_name from users u where u.user_id = :uuid";
        String userName = t.queryForObject(nameQuery, String.class, userId);

        ccrincipal.setUserId(userId);

        // jboss login, set the same fields as above except the notesToken
        String groupsQuery = "select G.GROUP_NAME from GROUPS_MEMBERS gm inner join groups g on (GM.GROUP_ID = g.id) where GM.USER_ID = :uuid";
        List<String> groupsList = t.queryForList(groupsQuery, String.class, userId);
        notesGroupList = new TreeSet<String>(groupsList);
        notesGroupList.add("*"); // add the * that notes does by default because we rely on this "group"

        if (log.isDebugEnabled()) {
            StringBuilder groupsText = new StringBuilder();
            groupsText.append("Adding ");
            groupsText.append(notesGroupList.size());
            groupsText.append(" groups: ");
            for (String group : groupsList) {
                groupsText.append(group);
                groupsText.append(", ");
            }

            log.debug(groupsText.toString());
        }

        // fill in the groups
        ccrincipal.setGroups(notesGroupList.toArray(new String[notesGroupList.size()]));

        this.updateDataFromJboss(ccrincipal, userId, t);

        // Set the user Principal's name to be the employee ID.
        ccrincipal.setUsername(ccrincipal.getUserId().toString());

    }

    /**
     * Extracts information from jboss tables and stores it in the {@link CcPrincipal} . This is only called on jboss login, for a Notes
     * login {@link #updateDataFromAddressbook(CcPrincipal, Session)} is used. Both this method and the noets version should set the same
     * fields.
     * 
     * @param ccPrincipal
     *            the {@link CcPrincipal} to update
     * @param userId
     *            the user_id
     * @param t
     *            {@link JdbcTemplate}
     */
    private void updateDataFromJboss(final CcPrincipalImpl ccPrincipal, Integer userId, JdbcTemplate t) {

        StringBuilder sql = new StringBuilder();
        sql.append("select u.user_name, u.first_name, u.middle_name, u.last_name, u.email ");
        sql.append("from table u ");
        sql.append("where u.user_id = :uuid ");

        String userInfoQuery = sql.toString();

        List<Map<String, Object>> results = t.queryForList(userInfoQuery, userId);
        if (results.isEmpty()) {
            throw new IllegalArgumentException("No users record found for " + userId);
        } else if (results.size() > 1) {
            throw new IllegalArgumentException(results.size() + " users record found for " + userId);
        }

        Map<String, Object> userInfo = results.iterator().next();

        ccPrincipal.setUserId(userId);
        ccPrincipal.setLastName((String) userInfo.get("LAST_NAME"));
        ccPrincipal.setMiddleInitial((String) userInfo.get("MIDDLE_NAME"));
        ccPrincipal.setFirstName((String) userInfo.get("FIRST_NAME"));
        ccPrincipal.setEmail((String) userInfo.get("EMAIL"));

    }

    /**
     * Lookup the datasource.
     * 
     * @return
     * @throws NamingException
     */
    private DataSource lookupDataSource(CcWebAuthenticationDetails wed) {
        WebApplicationContext ctx = WebApplicationContextUtils.getRequiredWebApplicationContext(wed.getRequest().getServletContext());
        return ctx.getBean(dataSourceName, DataSource.class);
    }

    /**
     * Is the password valid?
     * 
     * @param password
     *            the user entered password
     * @param passwordHash
     *            base64 encoded pw from the table
     * @param salt
     *            base 64 encoded salt from the table
     * @return
     */
    private boolean validateJbossPassword(String password, String passwordHash, String salt) {
        return passwordUtil.verifyPassword(passwordHash, salt, password);
    }

    /**
     * Set the data source name, if varying from ds-admin.
     * 
     * @param dataSourceName
     */
    public void setDataSourceName(String dataSourceName) {
        this.dataSourceName = dataSourceName;
    }

    public JdbcAuthenticationProvider setRolesFinder(RolesFinder rolesFinder) {
        this.rolesFinder = rolesFinder;
        return this;
    }

    public void setHostDbServiceProperties(HostDbServiceProperties hostDbServiceProperties) {
        this.hostDbServiceProperties = hostDbServiceProperties;
    }

}
