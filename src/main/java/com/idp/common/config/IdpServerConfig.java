package com.idp.common.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.google.gson.Gson;
import com.idp.common.config.json.GsonInitializer;
import com.idp.common.config.json.IdpHttpMessageConverter;

import reactor.netty.http.client.HttpClient;

@Configuration
public class IdpServerConfig implements WebMvcConfigurer {

	@Override
	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		converters.clear();
		converters.add(idpHttpMessageConverter());
	}

	@Bean
	public HttpMessageConverter<Object> idpHttpMessageConverter() {
		return new IdpHttpMessageConverter(gson());
	}

	@Bean
	public Gson gson() {
		return GsonInitializer.getInstance().getGson();
	}

	@Bean
	public WebClient webClient(ServletOAuth2AuthorizedClientExchangeFilterFunction clientExchangeFilterFunction) {
		return WebClient.builder()
				.clientConnector(new ReactorClientHttpConnector(
						HttpClient.create()
								.compress(true)
								.followRedirect(true)))
				.filter(clientExchangeFilterFunction)
				.build();
	}

	@Bean
	public ServletOAuth2AuthorizedClientExchangeFilterFunction clientExchangeFilterFunction(
			OAuth2AuthorizedClientManager authorizedClientManager) {

		return new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode()
				.refreshToken()
				.password()
				.clientCredentials()
				.build();

		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}
}
