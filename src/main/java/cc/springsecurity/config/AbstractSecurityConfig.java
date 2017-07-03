package cc.springsecurity.config;

import java.net.HttpCookie;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import cc.springsecurity.authentication.AbstractCcUserDetailsAuthenticationProvider;
import cc.springsecurity.authentication.sso.SsoAuthenticatedFilter;
import cc.springsecurity.authentication.sso.SsoAuthenticationSuccessHandler;
import cc.springsecurity.authentication.sso.SsoCookieInformation;
import cc.springsecurity.authentication.sso.SsoLogoutSuccessHandler;
import cc.springsecurity.authentication.sso.SsoPreAuthenticationProcessingFilter;
import cc.springsecurity.authentication.sso.SsoStorage;
import cc.springsecurity.authorization.RolesFinder;
import cc.springsecurity.authorization.rolematchers.MatcherRoles;
import cc.springsecurity.authorization.rolematchers.MatcherRolesContainer;
import cc.springsecurity.authorization.rolematchers.RequestMatcherContainer;
import cc.springsecurity.filters.RequestInfo;

/**
 * Configure web security. The concrete class should be in the war and annotated with EnableWebSecurity .
 * 
 * 
 * @author Chris Carcel
 * @see SecurityWebApplicationInitializer
 */
public abstract class AbstractSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SsoAuthenticationSuccessHandler ssoAuthenticationSuccessHandler;

    @Autowired
    private SsoPreAuthenticationProcessingFilter ssoPreAuthProcessingFilter;

    @Autowired
    private SsoLogoutSuccessHandler ssoLogoutSuccessHandler;

    @Autowired
    private SsoAuthenticatedFilter ssoAuthenticatedFilter;

    /**
     * Configure URLs to ignore for authentication.
     * 
     * @see #ignoringUrls()
     * @see RequestMatcherContainer
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        RequestMatcherContainer container = ignoringUrls();
        if (null != container) {
            List<RequestMatcher> list = container.getList();
            web.ignoring().requestMatchers(list.toArray(new RequestMatcher[list.size()]));
        }

        String loginPage = formLoginPage();
        if (null != loginPage) {
            web.ignoring().requestMatchers(new RegexRequestMatcher("^" + loginPage + ".*", null));
        }
    }

    /**
     * Over-ridden from the base class to configure http security.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // adds a filter to all requests which runs first and gives us information about the request accessible statically via a thread
        // local
        requestInformationFilter(http);

        // possibly disable csrf
        if (disableCsrf()) {
            http.csrf().disable();
        }

        // setup request authorization, i.e. which urls are secured to which roles
        authorizeRequests(http);

        // configure form login
        formLogin(http);

        // setup authentication against our authentication provider
        authentication(http);

        /*
         * Sso methods.
         */

        // configure the sso pre processing filter, this is what gives us sso across apps
        ssoPreprocessingFilter(http);

        // setup login success handler: creating an entry in sso storage
        loginSuccessHandler(http);

        // setup logout: cookie clearing, clearing entry in sso storage
        logoutHandler(http);

        // setup the filter that makes sure we are still authenticated
        ssoAuthenticatedFilter(http);

    }

    /**
     * Add the request info servlet as the first filter, making the host name and uuid accessible to all downstream code.
     * 
     * @param http
     */
    protected void requestInformationFilter(HttpSecurity http) {
        http.addFilterBefore(new RequestInfo(), WebAsyncManagerIntegrationFilter.class);
    }

    /**
     * Sets up the filter which runs on each request to make sure we are (still) logged in.
     * 
     * @param http
     */
    private void ssoAuthenticatedFilter(HttpSecurity http) {

        ssoAuthenticatedFilter.setCookieInformation(cookieInformation());
        ssoAuthenticatedFilter.setSsoStorage(ssoStorage());

        http.addFilterAfter(ssoAuthenticatedFilter, SessionManagementFilter.class);

    }

    /**
     * Return the {@link RequestMatcherContainer} which contains all the urls to ignore for authentication. These will allow anonymous
     * access. All other urls will require authentication. Sample code: <br>
     * <br>
     * <code>
     * return new RequestMatcherContainer().antPatterns("/css/**", "/fonts/**", "/js/**");
     * </code>
     * 
     * <br>
     * <br>
     * Note that if allowing by ip address, both ipv4 and ipv6 addresses should be considered. Also see {@link AndRequestMatcher} for
     * compound request matching.
     * 
     * @return request matchers to ignore
     */
    public abstract RequestMatcherContainer ignoringUrls();

    /**
     * Return the roles finder.
     * 
     * @return
     */
    public abstract RolesFinder rolesFinder();

    /**
     * Return the cookie information. Sample code <br>
     * <br>
     * <code>return new HardCodedCookieInformation("MyCookiename", null);</code>
     * 
     * @return
     */
    public abstract SsoCookieInformation cookieInformation();

    /**
     * Where we store the SSO information, either in a table or the file system or the like.
     * 
     * @return
     */
    public abstract SsoStorage ssoStorage();

    /**
     * Return the {@link MatcherRolesContainer} . This is a collection of urls and the roles that have access to those urls. All urls
     * require a login by default, except those found in {@link #ignoringUrls()} . Sample code: <br>
     * <br>
     * <code>return new MatcherRolesContainer().antPath("/app/**", "ADMIN");</code>
     * 
     * @return
     */
    public abstract MatcherRolesContainer rolesContainer();

    /**
     * Secures all urls (requiring a login) by default and adds "extra" security based on the results of {@link #rolesContainer()} .<br>
     * <br>
     * 
     * Example of how this code looks:<br>
     * <br>
     * <code>http.authorizeRequests().antMatchers("/admin/**").hasRole("admin").anyRequest().authenticated();</code>
     * 
     * @param http
     * @throws Exception
     */
    protected void authorizeRequests(HttpSecurity http) throws Exception {

        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry reg = http.authorizeRequests();

        MatcherRolesContainer container = rolesContainer();
        if (null != container && null != container.getRoles()) {
            for (MatcherRoles mr : container.getRoles()) {
                reg = reg.requestMatchers(mr.matcher()).hasAnyRole(mr.roles());
            }
        }

        reg.anyRequest().authenticated();

    }

    /**
     * By default, returns true to disable csrf.
     * 
     * @return
     */
    protected boolean disableCsrf() {
        return true;
    }

    /**
     * Sets up form login.
     * 
     * @see #formLoginDefaultSuccessUrl()
     * @see #formLoginPage()
     * @see #formLoginUserNameParameter()
     * @see #formLoginPasswordParameter()
     * @param http
     * @throws Exception
     */
    protected void formLogin(HttpSecurity http) throws Exception {
        FormLoginConfigurer<HttpSecurity> loginConfigurer = http.formLogin();

        String loginPage = formLoginPage();
        if (null != loginPage) {
            loginConfigurer = loginConfigurer.loginPage(loginPage);
        }

        String userNameParameter = formLoginUserNameParameter();
        if (null != userNameParameter) {
            loginConfigurer = loginConfigurer.usernameParameter(userNameParameter);
        }

        String passwordParameter = formLoginPasswordParameter();
        if (null != passwordParameter) {
            loginConfigurer = loginConfigurer.passwordParameter(passwordParameter);
        }

        String loginProcessingUrl = formLoginProcessingUrl();
        if (null != loginProcessingUrl) {
            loginConfigurer.loginProcessingUrl(loginProcessingUrl);
        }

        loginConfigurer.defaultSuccessUrl(formLoginDefaultSuccessUrl());
    }

    /**
     * Return the login processing url.
     * 
     * @return "/Login/j_security_check"
     */
    protected String formLoginProcessingUrl() {
        return "/Login/j_security_check";
    }

    /**
     * Return the name of the input field for the user name, that is: &lt;input name=&quot;x&quot;&gt; . Returns "j_username" by default for
     * backwards compatibility. If using a custom login page {@link #formLoginPage()} this must match the input field used there, otherwise
     * if spring is generating the login page, it will use this name.
     * 
     * @return "j_username"
     */
    protected String formLoginUserNameParameter() {
        return "j_username";
    }

    /**
     * Return the name of the input field for the password, that is: &lt;input name=&quot;x&quot;&gt; . Returns "j_password" by default for
     * backwards compatibility. If using a custom login page {@link #formLoginPage()} this must match the input field used there, otherwise
     * if spring is generating the login page, it will use this name.
     * 
     * @return "j_password"
     */
    protected String formLoginPasswordParameter() {
        return "j_password";
    }

    /**
     * Return the default url to use when someone logins in without first visiting a page which requires authentication. By default returns
     * "/" . Used in {@link #formLogin(HttpSecurity)}
     * 
     * @return "/"
     */
    protected String formLoginDefaultSuccessUrl() {
        return "/";
    }

    /**
     * Return the path to the Login form. Can be null, in which case the default spring login page will be used. Used in
     * {@link #formLogin(HttpSecurity)}
     * 
     * @return null by default, but could be /Login.jsp
     */
    protected String formLoginPage() {
        return null;
    }

    /**
     * Adds our {@link SsoPreAuthenticationProcessingFilter} . This is the object which handles SSO across wars.
     * 
     * @param http
     */
    protected void ssoPreprocessingFilter(HttpSecurity http) {

        ssoPreAuthProcessingFilter.setCookieInformation(cookieInformation());
        ssoPreAuthProcessingFilter.setRolesFinder(rolesFinder());
        ssoPreAuthProcessingFilter.setSsoStorage(ssoStorage());
        http.addFilterAt(ssoPreAuthProcessingFilter, AbstractPreAuthenticatedProcessingFilter.class);

    }

    /**
     * Setup our authentication providers.
     * 
     * @param http
     */
    protected void authentication(HttpSecurity http) {

        for (AbstractCcUserDetailsAuthenticationProvider provider : authenticationProviders()) {
            provider.setRolesFinder(rolesFinder());
            http.authenticationProvider(provider);
        }

    }

    /**
     * Return a non-null list of {@link AbstractCcUserDetailsAuthenticationProvider}s.
     * 
     * @return
     */
    protected abstract List<AbstractCcUserDetailsAuthenticationProvider> authenticationProviders();

    /**
     * Prevents spring from trying the {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider} when trying to
     * login. Similarly, code like so:
     * 
     * <pre>
     * AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
     * builder.parentAuthenticationManager(null);
     * </pre>
     * 
     * can be used in the {@link #authentication(HttpSecurity)} method. This method will only be used if none of our custom authentication
     * providers can authenticate the users. Therefore it simply throws an <code>BadCredentialsException</code>.
     */
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {

        class MyAuth implements AuthenticationManager {

            protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                throw new BadCredentialsException(
                        messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }

        }

        return new MyAuth();
    }

    /**
     * Setup a login success handler. This uses {@link #ssoStorage()} to store the SSO information.
     * 
     * @param http
     * @throws Exception
     * @see {@link CcWebAuthenticationDetailsSource} which gives us access to the entire http request when logging in
     */
    protected void loginSuccessHandler(HttpSecurity http) throws Exception {

        ssoAuthenticationSuccessHandler.setCookieInformation(cookieInformation());
        ssoAuthenticationSuccessHandler.setSsoStorage(ssoStorage());

        http.formLogin().successHandler(ssoAuthenticationSuccessHandler)
                .authenticationDetailsSource(new CcWebAuthenticationDetailsSource());

    }

    /**
     * Setup the logout success handler.
     * 
     * @param http
     * @throws Exception
     */
    protected void logoutHandler(HttpSecurity http) throws Exception {
        ssoLogoutSuccessHandler.setCookieInformation(cookieInformation());
        ssoLogoutSuccessHandler.setSsoStorage(ssoStorage());
        ssoLogoutSuccessHandler.setLogoutUrl(logoutSuccessUrl());
        ssoLogoutSuccessHandler.setCookiesToRemove(logoutCookies());

        // there is a "deleteCookies" method but that explicitly sets the path on the cookies to the context path
        http.logout().logoutSuccessHandler(ssoLogoutSuccessHandler);
    }

    /**
     * Return an unmodifiable set containing:
     * <ul>
     * <li>JSESSIONID</li>
     * <li><code>cookieInformation().name()</code></li>
     * </ul>
     * 
     * Need more? Override, call <code>super.logoutCookies()</code> and create a new set with additional values.
     * 
     * @return
     */
    protected Set<HttpCookie> logoutCookies() {
        Set<HttpCookie> c = new HashSet<>(2);

        SsoCookieInformation ci = cookieInformation();
        c.add(new HttpCookie(ci.name(), ci.domain()));
        c.add(new HttpCookie("JSESSIONID", null));

        return Collections.unmodifiableSet(c);

    }

    /**
     * The URL to send the user to on successful logout, defaults to "/"
     * 
     * @return "/"
     */
    protected String logoutSuccessUrl() {
        return "/";
    }

    /**
     * For use in spring boot, disable auto registration of our pre-auth filter.
     * 
     * @param filter
     * @return
     */
    @Bean
    public FilterRegistrationBean regPreAuth(SsoPreAuthenticationProcessingFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * For use in spring boot, disable auto registration of our sso filter.
     * 
     * @param filter
     * @return
     */
    @Bean
    public FilterRegistrationBean regAuth(SsoAuthenticatedFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }
}
