/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.guacamole.auth.sshkey;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.sshkey.user.SSHKeyUserContext;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

/**
 * Provider that stores per-user SSH keys in the database.
 */
public class SSHKeyAuthenticationProvider extends AbstractAuthenticationProvider {
    
    @Override
    public String getIdentifier() {
        return "sshkey";
    }
    
    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        return new SSHKeyUserContext(context);
    }
    
    @Override
    public UserContext redecorate(UserContext decorated, UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        if (decorated instanceof SSHKeyUserContext)
            return decorated;
        return new SSHKeyUserContext(context);
    }
    
}
