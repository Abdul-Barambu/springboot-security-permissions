//package com.abdul.SpringbootSecurityDemoAmCode.auth;
//
//import com.google.common.collect.Lists;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Repository;
//
//import java.util.List;
//import java.util.Optional;
//
//import static com.abdul.SpringbootSecurityDemoAmCode.security.ApplicationUserRole.*;
//
//@Repository("fake")
//public class FakeApplicationUserDaoService implements ApplicationUserDao{
//
//    private final PasswordEncoder passwordEncoder;
//
//    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    @Override
//    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
//        return Optional.empty();
//    }
//
//    private List<ApplicationUser> getApplicationUsers(){
//        List<ApplicationUser> applicationUsers = Lists.newArrayList(
////                new ApplicationUser(
////                        "Abdul",
////                        passwordEncoder.encode("password"),
////                        STUDENTS.getGrantedAuthorities(),
////                        true,
////                        true,
////                        true,
////                        true
////                ),
////                new ApplicationUser(
////                        "admin",
////                        passwordEncoder.encode("admin"),
////                        ADMIN.getGrantedAuthorities(),
////                        true,
////                        true,
////                        true,
////                        true
////                ),
////                new ApplicationUser(
////                        "tom",
////                        passwordEncoder.encode("tom"),
////                        ADMINTRAINEE.getGrantedAuthorities(),
////                        true,
////                        true,
////                        true,
////                        true
////                )
//        );
//        return applicationUsers;
//    }
//}
