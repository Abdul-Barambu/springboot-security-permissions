package com.abdul.SpringbootSecurityDemoAmCode.security;

import com.abdul.SpringbootSecurityDemoAmCode.jwt.JwtTokenVerifier;
import com.abdul.SpringbootSecurityDemoAmCode.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfiq extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
//    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfiq(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
//        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//  CSRF = CROSS SITE REQUEST FORGERY

//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrf().disable()
//                JWT Congiguration
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class) //add filter after the pass auth class
                .authorizeRequests()
                    .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //AntMatchers use to specify paths
                    .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENTS.name())
                    .anyRequest().authenticated();


//                FORM LOGIN CONFIGURATION

//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .usernameParameter("username")
//                    .passwordParameter("password")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) //extends remember me token
//                    .key("SomethinVerySecured")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");


//                You can also use antMatchers to specify httpMethods and path
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())

    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
//
//    @Bean
//    public DaoAuthenticationProvider daoAuthenticationProvider(){
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder);
//        provider.setUserDetailsService(applicationUserService);
//
//        return provider;
//    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        UserDetails AbdulUser = User.builder()
                .username("Abdul")
                .password(passwordEncoder.encode("password"))
                .authorities(ApplicationUserRole.STUDENTS.getGrantedAuthorities())
//                .roles(ApplicationUserRole.STUDENTS.name()) // ROLE_STUDENT USING THE ROLE ENUM CLASS
                .build();

        UserDetails AdminUser = User.builder()
                .username("Admin")
                .password(passwordEncoder.encode("admin"))
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMIN.name()) // ADMIN_STUDENT USING THE ROLE ENUM CLASS
                .build();

        UserDetails TomUser = User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("tom"))
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ADMINTRAINEE_STUDENT USING THE ROLE ENUM CLASS
                .build();

        return new InMemoryUserDetailsManager(
                AbdulUser,
                AdminUser,
                TomUser
        );
    }
}
