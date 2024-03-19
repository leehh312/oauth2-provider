package com.idp.handler.federated;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

public final class FederatedIdentityAuthenticationEntryPoint implements AuthenticationEntryPoint {
	private final AuthenticationEntryPoint delegate;

	public FederatedIdentityAuthenticationEntryPoint(String loginPageUrl) {
		this.delegate = new LoginUrlAuthenticationEntryPoint(loginPageUrl);
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
		this.delegate.commence(request, response, authenticationException);
	}
}
