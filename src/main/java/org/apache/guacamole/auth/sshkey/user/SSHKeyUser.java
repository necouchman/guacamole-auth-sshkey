/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.guacamole.auth.sshkey.user;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.MultilineField;
import org.apache.guacamole.form.PasswordField;
import org.apache.guacamole.net.auth.DelegatingUser;
import org.apache.guacamole.net.auth.User;

/**
 * User class that stores SSH Key material, but delegates the storage to
 * some other module.
 */
public class SSHKeyUser extends DelegatingUser {
    
    /**
     * The name of the attribute that stores the private SSH key.
     */
    public static final String SSH_KEY_ATTRIBUTE_NAME = "private-ssh-key";
    
    /**
     * The name of the attribute that stores the passphrase for the private
     * SSH key.
     */
    public static final String SSH_KEY_PASSPHRASE_ATTRIBUTE_NAME = "private-ssh-key-passphrase";
    
    /**
     * A collection of all attribute names associated with this user.
     */
    public static final Collection<String> ATTRIBUTE_NAMES =
            Arrays.asList(SSH_KEY_ATTRIBUTE_NAME, SSH_KEY_PASSPHRASE_ATTRIBUTE_NAME);
    
    /**
     * The Form that contains all fields that are configurable for this
     * User object.
     */
    public static final Form SSH_KEY_FORM = new Form("ssh-key-form",
            Arrays.asList(
                    new MultilineField(SSH_KEY_ATTRIBUTE_NAME),
                    new PasswordField(SSH_KEY_PASSPHRASE_ATTRIBUTE_NAME)
            ));
    
    /**
     * A collection of all forms that contain attributes for this User.
     */
    public static final Collection<Form> SSH_KEY_USER_FORMS =
            Collections.unmodifiableCollection(Arrays.asList(SSH_KEY_FORM));
    
    /**
     * Create a new SSHKeyUser that wraps the specified User object.
     * 
     * @param user
     *     The user object to decorate.
     */
    public SSHKeyUser(User user) {
        super(user);
    }
    
    /**
     * Return the original object that this class decorates.
     * 
     * @return
     *     The original User object that this class decorates.
     */
    public User getUndecorated() {
        return getDelegateUser();
    }
    
    @Override
    public Map<String, String> getAttributes() {
        Map <String, String> attributes = new HashMap<>(super.getAttributes());
        
        for (String attr : ATTRIBUTE_NAMES) {
            if (!attributes.containsKey(attr))
                attributes.put(attr, null);
        }
        return attributes;
    }
    
}
