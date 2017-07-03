package cc.springsecurity.config;

import java.io.Serializable;

import org.springframework.security.core.userdetails.UserDetails;

public interface CcPrincipal extends UserDetails, Serializable {

    Integer getUserId();

    /**
     * The full user name.
     * 
     * @return
     */
    String getUsername();

    /**
     * Getter for lastName.
     * 
     * @return The lastName.
     */
    String getLastName();

    /**
     * Getter for middleInitial.
     * 
     * @return The middleInitial.
     */
    String getMiddleInitial();

    /**
     * Getter for firstName.
     * 
     * @return The firstName.
     */
    String getFirstName();

    /**
     * Getter for email.
     * 
     * @return The email.
     */
    String getEmail();

    /**
     * Returns a sorted array of user group names suitable for Arrays.binarySearch.
     * 
     * @return
     */
    String[] getGroups();

}
