package cc.springsecurity.config;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Custom Princial class.
 * 
 * @author Chris Carcel
 * 
 */
@SuppressWarnings("serial")
public class CcPrincipalImpl implements Principal, CcPrincipal, UserDetails {

    /**
     * The user's full name.
     */
    private String userName;

    /**
     * The unique user id.
     */
    private Integer userId;

    /**
     * The lastName stores the user's last name.
     */
    private String lastName;
    /**
     * The middleInitial stores the user's middle initial or middle name.
     */
    private String middleInitial;
    /**
     * The firstName stores the user's first name.
     */
    private String firstName;
    /**
     * The email stores the user's email address.
     */
    private String email;

    /**
     * The list of group names someone is a member of.
     */
    private String[] groups;

    /**
     * Sorts the specified array and then updates the {@link #groups} field.
     * 
     * <p>
     * It is assumed that this array will not be (externally) modified in a way that would cause it to become unsorted.
     * </p>
     * 
     * @param groups
     *            May not be {@code null}. Elements should not be {@code null}.
     * @return
     * @see {@link #getGroups()}
     */
    public CcPrincipalImpl setGroups(String[] groups) {
        Arrays.sort(groups);
        this.groups = groups;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getGroups()
     */
    @Override
    public String[] getGroups() {
        return groups;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getEmployeeId()
     */
    @Override
    public Integer getUserId() {
        return userId;
    }

    public CcPrincipalImpl setUserId(Integer userId) {
        this.userId = userId;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getLastName()
     */
    @Override
    public String getLastName() {
        return lastName;
    }

    /**
     * Setter for lastName.
     * 
     * @param lastName
     *            The lastName to set.
     * @return
     */
    public CcPrincipalImpl setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getMiddleInitial()
     */
    @Override
    public String getMiddleInitial() {
        return middleInitial;
    }

    /**
     * Setter for middleInitial.
     * 
     * @param middleInitial
     *            The middleInitial to set.
     * @return
     */
    public CcPrincipalImpl setMiddleInitial(String middleInitial) {
        this.middleInitial = middleInitial;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getFirstName()
     */
    @Override
    public String getFirstName() {
        return firstName;
    }

    /**
     * Setter for firstName.
     * 
     * @param firstName
     *            The firstName to set.
     * @return
     */
    public CcPrincipalImpl setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getEmail()
     */
    @Override
    public String getEmail() {
        return email;
    }

    /**
     * Setter for email.
     * 
     * @param email
     *            The email to set.
     * @return
     */
    public CcPrincipalImpl setEmail(String email) {
        this.email = email;
        return this;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.security.config.CcPrincipal#getUsername()
     */
    @Override
    public String getUsername() {
        return this.userName;
    }

    /**
     * The user name the person logged in with.
     * 
     * @param username
     *            login user name
     * @return
     */
    public CcPrincipalImpl setUsername(String username) {
        this.userName = username;
        return this;
    }

    /**
     * <p>
     * WARN: This should only be used for debugging purposes. If you need a unique {@link String} identifier, you should use
     * {@link #getName()}.
     * </p>
     * 
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        // NOTE: toString() doesn't delegate to build() like equals(), hashCode(), getName(), etc. so that we can have different output for
        // debugging.
        ToStringBuilder tsb = new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE);
        tsb.append("employeeId", getUserId());
        tsb.append("username", getUsername());
        return tsb.toString();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<SimpleGrantedAuthority> result;
        if (null != this.groups) {
            result = new HashSet<SimpleGrantedAuthority>(groups.length);
            for (String group : groups) {
                result.add(new SimpleGrantedAuthority("GROUP_" + group));
            }
        } else {
            result = null;
        }
        return result;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // TO DO could implement in the real world
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return this.userName;
    }
}
