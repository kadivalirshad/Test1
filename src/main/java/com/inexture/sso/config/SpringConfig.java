package com.inexture.sso.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SpringConfig {
    
   
	@Autowired
	private OAuthSuccessHandler authSuccessHandler;
	
	 @Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        http.authorizeHttpRequests(auth -> auth
	                .requestMatchers("/login").permitAll()
	                .anyRequest().authenticated()
	            )
	            .formLogin(form -> form
	                .loginPage("/login")
	                .permitAll()
	            )
	            .oauth2Login(oauth2 -> {oauth2
	                .loginPage("/login");
	                oauth2.successHandler(authSuccessHandler);
	                //oauth2.failureHandler(authSuccessHandler);
	            })
	            .logout(logout -> logout
	                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	                .permitAll()
	            );
	            

	        return http.build();
	    }
	
	 
//	 @Bean
//		public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//			return configuration.getAuthenticationManager();
//		}
	 
	 @Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/images/**", "/js/**", "/css/**", "/webjars/**");
		}


}
