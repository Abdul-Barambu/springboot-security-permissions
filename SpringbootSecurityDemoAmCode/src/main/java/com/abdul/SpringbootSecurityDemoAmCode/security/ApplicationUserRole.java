package com.abdul.SpringbootSecurityDemoAmCode.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.abdul.SpringbootSecurityDemoAmCode.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
//    Create roles
    STUDENTS(Sets.newHashSet()), // No permissions
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)), // Set permissions
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ)); // Set permissions


    //    define the set of permissions and define constructor and getter
    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return permissions;
    }

//    ########## USING ANNOTATIONS ###########

//    YOU CAN USE PERMISSION BASED AUTHENTICATION ON A METHOD LEVEL USING ANNOATATIONS IN YOUR CONTOLLER
//    USING @PreAuthorised("roles, athorities('pass the roles')")
//    ANNOTATE YOUR APPSECURITYCONFIG CLASS WITH ENABLGLOBALMETHODSEC(PRE-POST-ENABLED = TRUE)
}
