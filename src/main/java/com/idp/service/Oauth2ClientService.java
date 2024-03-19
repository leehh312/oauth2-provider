package com.idp.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.idp.common.IdpParameterNames;
import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.dto.Oauth2Token;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;
import com.idp.repository.Oauth2ClientRepository;

@Service
public class Oauth2ClientService {
    private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";

    private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 32);
    public static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 48);

    @Value("${idp.oauth2.provider-url}")
    private String provider_issue_url;

    @Value("${idp.oauth2.token.ttl}")
    private long token_ttl;

    private final ProviderSettings providerSettings;

    private final JwtEncoder jwtEncoder;

    private final Oauth2ClientRepository clientRepository;

    private final OAuth2AuthorizationService authorizationService;

    private final ObjectMapper objectMapper;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final PasswordEncoder passwordEncoder;

    public static final String DEFAULT_IDP_UUID = "17b34e2a-9595-41d7-a761-30607fe5ea74";
    public static final String DEFAULT_IDP_CLIENTNAME = "idp";

    public Oauth2ClientService(JwtEncoder jwtEncoder, ProviderSettings providerSettings,
            Oauth2ClientRepository ouath2Repository, OAuth2AuthorizationService authorizationService,
            PasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.providerSettings = providerSettings;
        this.clientRepository = ouath2Repository;
        this.authorizationService = authorizationService;
        this.passwordEncoder = passwordEncoder;
        this.tokenGenerator = new JwtGenerator(jwtEncoder);
        this.objectMapper = new ObjectMapper();
    }

    @PostConstruct
    private void init() {
        ClassLoader classLoader = JdbcRegisteredClientRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        RegisteredClient idpClient = RegisteredClient.withId(DEFAULT_IDP_UUID)
                .clientId(CLIENT_ID_GENERATOR.generateKey())
                .clientIdIssuedAt(Instant.now())
                .clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
                .clientName(DEFAULT_IDP_CLIENTNAME)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("client.create")
                .clientSettings(
                        ClientSettings.builder()
                                .jwkSetUrl(provider_issue_url.concat(providerSettings.getJwkSetEndpoint()))
                                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                                .build())
                .build();

        clientRepository.save(idpClient);
    }

    public RegisteredClient registerClient(OidcClientRegistration clientRegistration, String secretKey) {
        String registerId = UUID.randomUUID().toString();
        if (Objects.nonNull(clientRepository.findById(registerId))) {
            registerClient(clientRegistration, secretKey);
        }

        RegisteredClient.Builder builder = RegisteredClient.withId(registerId)
                .clientId(CLIENT_ID_GENERATOR.generateKey())
                .clientIdIssuedAt(Instant.now())
                .clientName(clientRegistration.getClientName())
                .clientSecret(this.passwordEncoder.encode(secretKey));

        builder.redirectUris(redirectUris -> redirectUris.addAll(clientRegistration.getRedirectUris()));

        String authenticationMethod = clientRegistration.getTokenEndpointAuthenticationMethod();
        if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(authenticationMethod)) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod)) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        }

        if (!CollectionUtils.isEmpty(clientRegistration.getGrantTypes())) {
            builder.authorizationGrantTypes(authorizationGrantTypes -> clientRegistration.getGrantTypes()
                    .forEach(grantType -> authorizationGrantTypes.add(new AuthorizationGrantType(grantType))));
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        }
        if (CollectionUtils.isEmpty(clientRegistration.getResponseTypes()) ||
                clientRegistration.getResponseTypes().contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        }

        if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
            builder.scopes(scopes -> scopes.addAll(clientRegistration.getScopes()));
        }

        // 클라이언트 기타 설정
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireAuthorizationConsent(true);

        if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(authenticationMethod)) {
            MacAlgorithm macAlgorithm = MacAlgorithm
                    .from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
            if (macAlgorithm == null) {
                macAlgorithm = MacAlgorithm.HS256;
            }
            clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(macAlgorithm);
        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod)) {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm
                    .from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
            if (signatureAlgorithm == null) {
                signatureAlgorithm = SignatureAlgorithm.RS256;
            }
            clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(signatureAlgorithm);
            clientSettingsBuilder.jwkSetUrl(clientRegistration.getJwkSetUrl().toString());
        }

        // 클라이언트 토큰 설정
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(token_ttl == 0 ? Duration.ofSeconds(86400L) : Duration.ofSeconds(token_ttl))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        RegisteredClient newRegisteredClient = builder.clientSettings(clientSettingsBuilder.build())
                .tokenSettings(tokenSettings)
                .build();

        clientRepository.save(newRegisteredClient);

        return newRegisteredClient;
    }

    public OAuth2Authorization registerAccessToken(RegisteredClient registeredClient,
            JwtAuthenticationToken authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                registeredClient.getClientAuthenticationMethods().iterator().next(),
                registeredClient.getClientSecret());

        Set<String> authorizedScopes = new HashSet<>();
        authorizedScopes.add("client.read");
        authorizedScopes = Collections.unmodifiableSet(authorizedScopes);

        ProviderContext providerContext = new ProviderContext(providerSettings, null);
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .providerContext(providerContext)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
      
        OAuth2Token registrationAccessToken = this.tokenGenerator.generate(tokenContext);
        if (Objects.isNull(registrationAccessToken)) {
            IdpError error = CommonUtils.generateError(IdpStatus.FAIL_GENERATE_ACCESSTOKEN);
            error.setErrorUri(ERROR_URI);
            throw new IdpApiException(error);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                registrationAccessToken.getTokenValue(), registrationAccessToken.getIssuedAt(),
                registrationAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);

        if (registrationAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken,
                    (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) registrationAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        authorization = invalidate(authorization, authorization.getAccessToken().getToken());
        if (authorization.getRefreshToken() != null) {
            authorization = invalidate(authorization, authorization.getRefreshToken().getToken());
        }

        this.authorizationService.save(authorization);

        return authorization;
    }

    public OidcClientRegistration.Builder buildRegistration(RegisteredClient registeredClient) {

        OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientName(registeredClient.getClientName());

        if (registeredClient.getClientSecret() != null) {
            builder.clientSecret(registeredClient.getClientSecret());
        }

        builder.redirectUris(redirectUris -> redirectUris.addAll(registeredClient.getRedirectUris()));

        builder.grantTypes(grantTypes -> registeredClient.getAuthorizationGrantTypes()
                .forEach(authorizationGrantType -> grantTypes.add(authorizationGrantType.getValue())));

        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            builder.responseType(OAuth2AuthorizationResponseType.CODE.getValue());
        }

        if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
            builder.scopes(scopes -> scopes.addAll(registeredClient.getScopes()));
        }

        String registrationClientUri = UriComponentsBuilder.fromUriString(providerSettings.getIssuer())
                .path(providerSettings.getOidcClientRegistrationEndpoint())
                .queryParam(IdpParameterNames.CLIENT_ID, registeredClient.getClientId())
                .toUriString();

        builder.tokenEndpointAuthenticationMethod(
                registeredClient.getClientAuthenticationMethods().iterator().next().getValue())
                .idTokenSignedResponseAlgorithm(
                        registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName())
                .registrationClientUrl(registrationClientUri);

        ClientSettings clientSettings = registeredClient.getClientSettings();

        if (clientSettings.getJwkSetUrl() != null) {
            builder.jwkSetUrl(clientSettings.getJwkSetUrl());
        }

        if (clientSettings.getTokenEndpointAuthenticationSigningAlgorithm() != null) {
            builder.tokenEndpointAuthenticationSigningAlgorithm(
                    clientSettings.getTokenEndpointAuthenticationSigningAlgorithm().getName());
        }

        return builder;
    }

    public OidcClientRegistration convertOidcClientRegistration(String clientName, List<String> redirectUris) {
        if (!isValidClientName(clientName)){
            IdpError error = CommonUtils.generateError(IdpStatus.NULL_OAUTH2_CLIENT_NAME);
            throw new IdpApiException(error);
        }

        if (!isValidRedirectUris(redirectUris)){
            IdpError error = CommonUtils.generateError(IdpStatus.INVALID_OAUTH2_REQUEST_URI);
            throw new IdpApiException(error);
        }

        return OidcClientRegistration.builder()
                .clientName(clientName)
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .grantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
                .grantType(AuthorizationGrantType.JWT_BEARER.getValue())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.ADDRESS)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PHONE)
                .scope(OidcScopes.PROFILE)
                .redirectUris(redirect_uris -> redirect_uris.addAll(redirectUris))
                .build();
    }

    public Jwt createJwt() {
        RegisteredClient registeredClient = getIdpClient();
        
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

        String audience = UriComponentsBuilder.fromUriString(providerSettings.getIssuer())
                .path(this.providerSettings.getTokenEndpoint())
                .build()
                .toUriString();

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer(registeredClient.getClientId())
                .subject(registeredClient.getClientId())
                .audience(Collections.singletonList(audience))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));
    }

    public OAuth2Authorization findByToken(Oauth2Token ouath2Token) {
        return authorizationService.findByToken(ouath2Token.getAccessToken(), OAuth2TokenType.ACCESS_TOKEN);
    }

    public boolean isValidClientName(String clientName) {
        if (!StringUtils.hasText(clientName))
            return false;

        return true;
    }

    public boolean isValidRedirectUris(List<String> redirectUris) {
        if (Objects.isNull(redirectUris) || CollectionUtils.isEmpty(redirectUris)) {
            return false;
        }

        for (String redirectUri : redirectUris) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                if (validRedirectUri.getFragment() != null) {
                    return false;
                }
            } catch (URISyntaxException ex) {
                return false;
            }
        }

        return true;
    }

    private RegisteredClient getIdpClient() {
        return clientRepository.findById(DEFAULT_IDP_UUID);
    }

    private <T extends OAuth2Token> OAuth2Authorization invalidate(OAuth2Authorization authorization, T token) {
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                .token(token,
                        (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            authorizationBuilder.token(
                    authorization.getAccessToken().getToken(),
                    (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
                    .getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                authorizationBuilder.token(
                        authorizationCode.getToken(),
                        (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
            }
        }

        return authorizationBuilder.build();
    }
}
