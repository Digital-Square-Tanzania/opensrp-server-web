/**
 *
 */
package org.opensrp.web.config.security;

import org.opensrp.api.domain.User;
import org.opensrp.connector.openmrs.service.OpenmrsUserService;
import org.opensrp.web.security.OauthAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * @author Samuel Githengi created on 07/02/20
 */
@Component
public class OpenmrsUserDetailsService implements UserDetailsService {
    public static final String USER_HASH_KEY = "_user";

    @Autowired
    private OpenmrsUserService openmrsUserService;

    @Autowired
    private OauthAuthenticationProvider authenticationProvider;

    @Resource(name = "redisTemplate")
    private HashOperations<String, String, User> hashOps;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(OpenmrsUserDetailsService.class.getSimpleName() + " : loadUserByUsername = " + username);

        User user = null;

        if (hashOps.hasKey(username, USER_HASH_KEY)) {
            System.out.println(OpenmrsUserDetailsService.class.getSimpleName() + " : Obtained the user details from Redis");
            user = hashOps.get(username, USER_HASH_KEY);
        }

        if (user == null) {

            System.out.println(OpenmrsUserDetailsService.class.getSimpleName() + " : Loading user from openmrs service");
            user = openmrsUserService.getUser(username);
            if (user == null) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            System.out.println(OpenmrsUserDetailsService.class.getSimpleName() + " : Caching user details in Redis for subsequent requests");
            // Cache the user for subsequent requests.
            hashOps.put(username, USER_HASH_KEY, user);
        }

        // Note: Using an empty string for password may be acceptable if authentication is done via tokens.
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                "",
                authenticationProvider.getRolesAsAuthorities(user)
        );
    }

}
