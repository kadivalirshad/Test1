package com.inexture.sso.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

//	@Override
//	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
//			AuthenticationException exception) throws IOException, ServletException {
//		
//		System.err.println(exception.getLocalizedMessage());
//	}


	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		DefaultOAuth2User userAuth = (DefaultOAuth2User) authentication.getPrincipal();
		OAuth2AuthenticationToken authentictionToken = (OAuth2AuthenticationToken) authentication;
		String authorizationId = authentictionToken.getAuthorizedClientRegistrationId();
		String email = null;
		String name = null;
		

		response.sendRedirect("/login");
	}

}
