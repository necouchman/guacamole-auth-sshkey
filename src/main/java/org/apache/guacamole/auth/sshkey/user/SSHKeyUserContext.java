/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.guacamole.auth.sshkey.user;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;

/**
 * UserContext class that delegates the storage of members to another
 * module, and decorates objects within those modules.
 */
public class SSHKeyUserContext extends DelegatingUserContext {
    
    /**
     * Create a new SSHKeyUserContext that decorates the specified
     * UserContext.
     * 
     * @param userContext 
     *     The UserContext object to decorate.
     */
    public SSHKeyUserContext(UserContext userContext) {
        super(userContext);
    }
    
    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {
        return new DecoratingDirectory<User>(super.getUserDirectory()) {

            @Override
            protected User decorate(User object) {
                if (self().getIdentifier().equals(object.getIdentifier()))
                    return new SSHKeyUser(object);
                return object;
            }

            @Override
            protected User undecorate(User object) {
                assert(object instanceof SSHKeyUser);
                return ((SSHKeyUser) object).getUndecorated();
            }

        };
    }
    
    @Override
    public Collection<Form> getUserAttributes() {
        Collection<Form> allAttributes = new HashSet<>(super.getUserAttributes());
        allAttributes.addAll(SSHKeyUser.SSH_KEY_USER_FORMS);
        return Collections.unmodifiableCollection(allAttributes);
    }
    
}
