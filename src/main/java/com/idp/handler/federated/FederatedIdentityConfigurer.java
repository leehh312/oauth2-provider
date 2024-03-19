package com.idp.handler.federated;

import java.util.Objects;
import java.util.function.Consumer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;

import com.idp.common.IdpStatus;
import com.idp.common.config.security.Oauth2ConstantsConfig;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;

public final class FederatedIdentityConfigurer extends AbstractHttpConfigurer<FederatedIdentityConfigurer, HttpSecurity> {

	private String loginPageUrl = Oauth2ConstantsConfig.MORPHEUS_IDP_LOGINPAGE;

	private String authorizationRequestUri;

	private Consumer<OAuth2User> oAuth2UserService;

	private AuthenticationFailureHandler authenticationFailureHandler;

	public FederatedIdentityConfigurer loginPageUrl(String loginPageUrl) {
		if(!StringUtils.hasText(loginPageUrl)){
			IdpError error = CommonUtils.generateError(IdpStatus.NULL_LOGIN_PAGE_URL);
			throw new IdpApiException(error);
		}

		this.loginPageUrl = loginPageUrl;
		return this;
	}

	public FederatedIdentityConfigurer authorizationRequestUri(String authorizationRequestUri) {
		if(!StringUtils.hasText(authorizationRequestUri)){
			IdpError error = CommonUtils.generateError(IdpStatus.NULL_FEDERATED_AUTHORIZATION_REQUEST_URI);
			throw new IdpApiException(error);
		}

		this.authorizationRequestUri = authorizationRequestUri;
		return this;
	}

	public FederatedIdentityConfigurer oauth2UserHandler(Consumer<OAuth2User> oAuth2UserService) {
		if(Objects.isNull(oAuth2UserService)){
			IdpError error = CommonUtils.generateError(IdpStatus.NULL_FEDERATED_OAUTH2_USER_SERVICE);
			throw new IdpApiException(error);
		}

		this.oAuth2UserService = oAuth2UserService;
		return this;
	}

	public FederatedIdentityConfigurer authenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		if(Objects.isNull(authenticationFailureHandler)){
			IdpError error = CommonUtils.generateError(IdpStatus.NULL_FEDERATED_AUTHENTICATION_FAIL_HANDLER);
			throw new IdpApiException(error);
		}

		this.authenticationFailureHandler = authenticationFailureHandler;
		return this;
	}
	 
	@Override
	public void init(HttpSecurity http) throws Exception {
		FederatedIdentityAuthenticationEntryPoint authenticationEntryPoint =
			new FederatedIdentityAuthenticationEntryPoint(this.loginPageUrl);

		FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler =
			new FederatedIdentityAuthenticationSuccessHandler(oAuth2UserService);

		http.exceptionHandling(exceptionHandling ->
				exceptionHandling.authenticationEntryPoint(authenticationEntryPoint)
			)
			.oauth2Login(oauth2Login -> {
				oauth2Login.successHandler(federatedIdentityAuthenticationSuccessHandler);
                oauth2Login.failureHandler(authenticationFailureHandler);
				if (this.authorizationRequestUri != null) {
					String baseUri = this.authorizationRequestUri.replace("/{registrationId}", "");
					oauth2Login.authorizationEndpoint(authorizationEndpoint -> 
						authorizationEndpoint.baseUri(baseUri)
					);
				}
			});
	}
}
