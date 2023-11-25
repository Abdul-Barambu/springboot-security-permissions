//package com.abdul.SpringbootSecurityDemoAmCode.auth;
//
//import com.google.common.collect.Sets;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//
//import java.util.Collection;
//import java.util.Set;
//
//public class ApplicationUser implements UserDetails {
//
////    Create a variable of each methode...
//
//    private final Set<? extends GrantedAuthority> grantedAuthorities;
//
//    public ApplicationUser(Set<? extends GrantedAuthority> grantedAuthorities,
//                           String password,
//                           String username,
//                           boolean isAccountNonExpired,
//                           boolean isAccountNonLocked,
//                           boolean isCredentialsNonExpired,
//                           boolean isEnabled) {
//        this.grantedAuthorities = grantedAuthorities;
//        this.password = password;
//        this.username = username;
//        this.isAccountNonExpired = isAccountNonExpired;
//        this.isAccountNonLocked = isAccountNonLocked;
//        this.isCredentialsNonExpired = isCredentialsNonExpired;
//        this.isEnabled = isEnabled;
//    }
//
//    private final String password;
//    private final String username;
//    private final boolean isAccountNonExpired;
//    private final boolean isAccountNonLocked;
//    private final boolean isCredentialsNonExpired;
//    private  final boolean isEnabled;
//
//
//
//// return all the variables created
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return grantedAuthorities;
//    }
//
//    @Override
//    public String getPassword() {
//        return password;
//    }
//
//    @Override
//    public String getUsername() {
//        return username;
//    }
//
//    @Override
//    public boolean isAccountNonExpired() {
//        return isAccountNonExpired;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return isAccountNonLocked;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return isCredentialsNonExpired;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return isEnabled;
//    }
//}
