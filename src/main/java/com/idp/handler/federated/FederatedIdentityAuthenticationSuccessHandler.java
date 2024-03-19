package com.idp.handler.federated;

import java.io.IOException;
import java.util.function.Consumer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public final class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

	private Consumer<OAuth2User> oAuth2UserService;

	public FederatedIdentityAuthenticationSuccessHandler(Consumer<OAuth2User> oAuth2UserService) {
		this.oAuth2UserService = oAuth2UserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		if (authentication instanceof OAuth2AuthenticationToken) {
			if (authentication.getPrincipal() instanceof OidcUser) {
				oAuth2UserService.accept((OidcUser) authentication.getPrincipal());
			} else if (authentication.getPrincipal() instanceof OAuth2User) {
				oAuth2UserService.accept((OAuth2User) authentication.getPrincipal());
			}
		}

		this.delegate.onAuthenticationSuccess(request, response, authentication);
	}
}
