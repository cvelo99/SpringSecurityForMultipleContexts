This project contains a framework for developing java web applications secured by Spring security. It addresses the need for that security to span multiple web applications.

A good starting point is the class AbstractSecurityConfig. A concrete implementation of this class must exist in each war. It contains all the configuration needed to secure one or more web applications.

Since spring security, and generally java security, only secure wars individually, requiring a login to each war, there are some hurdles we need to jump through to secure multiple wars with one login:

1) we need to store authentication information somewhere. This is typically done in memory as part of the ServletContext but that will not work across wars. This project provides the interface SsoStorage to allow us to store sso information in an external system. There are two concrete implementations provided, both suitable only for testing. For production use, consider using a table or in memory database.

2) we need to customize the cookie used to determine who the user is, since JSESSIONID is tied to just one war. See the SsoCookieInformation class.

3) we need to check for the user in the SsoStorage system and use that login information. See SsoPreAuthenticationProcessingFilter .

4) logout needs to remove the user from SsoStorage.