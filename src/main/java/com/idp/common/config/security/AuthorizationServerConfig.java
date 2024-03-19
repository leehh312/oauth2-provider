package com.idp.common.config.security;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.idp.common.config.json.JacksonCommonMixin;
import com.idp.common.dto.entity.IdpUser;
import com.idp.common.util.Jwks;
import com.idp.handler.error.Oauth2ErrorResponseHandler;
import com.idp.handler.error.UserSessionInformationExpiredStrategy;
import com.idp.handler.IdentityIdTokenHandler;
import com.idp.handler.LoginAuthenticationSuccessHandler;
import com.idp.handler.error.LoginAuthenticationFailureHandler;
import com.idp.handler.federated.FederatedIdentityAuthenticationSuccessHandler;
import com.idp.handler.federated.FederatedIdentityConfigurer;
import com.idp.service.JpaUserDetailsService;

import java.io.File;
import java.util.EventListener;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/favicon.ico");
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder
            , DaoAuthenticationProvider authenticationProvider
            , Gson gson) throws Exception {

        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        authorizationServerConfigurer
                .clientAuthentication(client -> {
                    client.errorResponseHandler(new Oauth2ErrorResponseHandler(gson));
                })
                .authorizationEndpoint(authorizationEndpoint -> {
                    authorizationEndpoint.errorResponseHandler(new Oauth2ErrorResponseHandler(gson));
                })
                .tokenEndpoint(token -> {
                    token.errorResponseHandler(new Oauth2ErrorResponseHandler(gson));
                })
                .oidc(oidc -> {
                    oidc.clientRegistrationEndpoint(Customizer.withDefaults());
                    oidc.userInfoEndpoint(Customizer.withDefaults());
                });
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        
        return http.requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer).and()
                .apply(new FederatedIdentityConfigurer()).and()
                .authenticationProvider(authenticationProvider)
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .build();
    }

    /**
     * sessionManagement().maximumSessions() 적용되어있을 시
     * login --> logout --> 재 login시
     * "Maximum sessions of 1 for this principal exceeded" 버그 발생 이슈
     * 원인 ==> LogoutFilter에서 logout 시 세션을 무효화 하더라도 SessionRegistry에 저장된 SessionInformation까지 관리하지 않는 이유로 발생
     * 스프링 ioc 컨테이너에 ServletListenerRegistrationBean 등록하면 버그 해결
     * 
     * @return ServletListenerRegistrationBean
     */
    @Bean
    public ServletListenerRegistrationBean<EventListener> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<EventListener>(new HttpSessionEventPublisher());
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new IdentityIdTokenHandler();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(JpaUserDetailsService jpaUserDetailsService
            , PasswordEncoder passwordEncoder) throws Exception {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(jpaUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setHideUserNotFoundExceptions(false);
        authenticationProvider.afterPropertiesSet();

        return authenticationProvider;
    }

    @Bean
    public JdbcTokenRepositoryImpl tokenRepository(JdbcTemplate jdbcTemplate) {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setJdbcTemplate(jdbcTemplate);
        return tokenRepository;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(IdpUser.class, JacksonCommonMixin.class);
        
        OAuth2AuthorizationRowMapper authorizationRowMapper 
                = new OAuth2AuthorizationRowMapper(registeredClientRepository);
        authorizationRowMapper.setObjectMapper(objectMapper);
        authorizationRowMapper.setLobHandler(new DefaultLobHandler());

        JdbcOAuth2AuthorizationService service = new JdbcOAuth2AuthorizationService(jdbcTemplate,
                registeredClientRepository);
        service.setAuthorizationRowMapper(authorizationRowMapper);
        return service;
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService(JdbcOperations jdbcOperations,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean("jwkSource")
    public JWKSource<SecurityContext> jwkSource(Oauth2ConstantsConfig oauth2ConstantsConfig) {
        File file = new File(getClass().getClassLoader().getResource(oauth2ConstantsConfig.getOauth2PfxPath()).getPath());
        RSAKey rsaKey = Jwks.getRsa(file, oauth2ConstantsConfig.getOauth2PfxAlias(), oauth2ConstantsConfig.getOauth2PfxPass());
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
    
    @Bean
    public ProviderSettings providerSettings(Oauth2ConstantsConfig oauth2ConstantsConfig) {
        return ProviderSettings.builder()
                .issuer(oauth2ConstantsConfig.getProvider_issue_url())
                .build();
    }

    @Bean
    public FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler(
            Consumer<OAuth2User> oAuth2UserService) {
        return new FederatedIdentityAuthenticationSuccessHandler(oAuth2UserService);
    }

    @Bean
    public LoginAuthenticationFailureHandler loginAuthenticationFailureHandler(
            JpaUserDetailsService jpaUserDetailsService) {
        return new LoginAuthenticationFailureHandler(jpaUserDetailsService);
    }

    @Bean
    public LoginAuthenticationSuccessHandler loginAuthenticationSuccessHandler(
            JpaUserDetailsService jpaUserDetailsService
            , Oauth2ConstantsConfig oauth2ConstantsConfig) {
        return new LoginAuthenticationSuccessHandler(jpaUserDetailsService, oauth2ConstantsConfig, Oauth2ConstantsConfig.DEFAULT_SUCCESS_URL);
    }

    @Bean
    public UserSessionInformationExpiredStrategy userSessionInformationExpiredStrategy(
        SessionRegistry sessionRegistry) {
        return new UserSessionInformationExpiredStrategy(sessionRegistry);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        // 1. 세션으로 관리
        HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();

        // 2. 쿠리로 관리
        // CookieCsrfTokenRepository tokenRepository = new CookieCsrfTokenRepository();
        // tokenRepository.setCookieHttpOnly(false);
        // tokenRepository.setSecure(true);
        return tokenRepository;
    }
}
