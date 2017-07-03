package cc.springsecurity.config;

/**
 * The existence of this class triggers form based security. The services api is used in spring-web jar,
 * META-INF/services/javax.servlet.ServletContainerInitializer . This and the concrete instance of {@link AbstractSecurityConfig} are
 * required for web based auth.
 * 
 * @author Chris Carcel
 *
 */
public class SecurityWebApplicationInitializer /* extends AbstractSecurityWebApplicationInitializer */ {

}

// TODO figure out what is going on here
