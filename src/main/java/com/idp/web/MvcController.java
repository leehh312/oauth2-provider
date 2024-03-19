package com.idp.web;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import javax.validation.constraints.NotNull;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import com.google.gson.Gson;
import com.idp.common.IdpParameterNames;
import com.idp.common.IdpStatus;
import com.idp.common.config.security.Oauth2ConstantsConfig;
import com.idp.common.dto.IdpError;
import com.idp.common.dto.OidcClient;
import com.idp.common.dto.Oauth2Token;
import com.idp.common.dto.UserSignInfo;
import com.idp.common.dto.entity.EmailToken;
import com.idp.common.dto.entity.IdpUser;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;
import com.idp.service.JpaUserDetailsService;
import com.idp.service.Oauth2ClientService;
import com.idp.service.email.EmailTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Validated
@Controller
@RequiredArgsConstructor
@Slf4j
public class MvcController {
    private final static String DEFAULT_EMAIL_AUTHENTICATION_MESSAGE = "이메일 인증 후 서비스 이용하실 수 있습니다. 회원님께서 등록하신 이메일에 방문하여 발송한 메일에서 인증 바랍니다.";

    private final Oauth2ClientService oauth2Service;

    private final WebClient webClient;

    private final Gson gson;

    private final JpaUserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final SessionRegistry sessionRegistry;
    
    private final Oauth2ConstantsConfig oauth2ConstantsConfig;

    private final EmailTokenService emailTokenService;

    @GetMapping("/")
    public String viewHomePage() {
        return "index";
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response) {
        for(Cookie cookie : request.getCookies()){
            log.debug("################### cookie key: {}, cookie val: {}",cookie.getName(), cookie.getValue());
        }    
        
        return "login";
    }

    @PostMapping(value = "/login", params = { IdpParameterNames.ERROR, IdpParameterNames.ERROR_DESCRIPTION })
    public String authorizationFailed(Model model, HttpServletRequest request,
            @RequestParam(IdpParameterNames.ERROR) String error,
            @RequestParam(IdpParameterNames.ERROR_DESCRIPTION) String error_description,
            @RequestParam(name = IdpParameterNames.EXISTS_USER, required = false) Boolean exists_user)
            throws UnsupportedEncodingException {
        
        model.addAttribute(IdpParameterNames.EXISTS_USER, exists_user);
        model.addAttribute(IdpParameterNames.ERROR, error);
        model.addAttribute(IdpParameterNames.ERROR_DESCRIPTION, error_description);
        model.addAttribute(IdpParameterNames.USERNAME, request.getParameter(IdpParameterNames.USERNAME));
        model.addAttribute(IdpParameterNames.PASSWORD, request.getParameter(IdpParameterNames.PASSWORD));
        model.addAttribute(oauth2ConstantsConfig.getRememberKeyname(), request.getParameter(oauth2ConstantsConfig.getRememberKeyname()));

        return "login";
    }

    @ResponseBody
    @PostMapping(value = "/login/force")
    public ResponseEntity<?> forceLogin(UserSignInfo userInfo
                        , HttpServletRequest request
                        , HttpServletResponse response) {
        IdpUser idpUser = (IdpUser) userDetailsService.loadUserByUsername(userInfo.getUsername());
        List<SessionInformation> list = sessionRegistry.getAllSessions(idpUser, false);
        for(SessionInformation information : list){
            information.expireNow();
        }

        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/signup")
    public String signupPage() {
        return "signup";
    }
 
    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void signup(UserSignInfo userInfo, HttpServletResponse response) {
        IdpUser user = IdpUser.withUserInfo(userInfo, passwordEncoder)
                .accountRemainingCount(oauth2ConstantsConfig.getRemainingCount())
                .enabled(false)
                .build();
        
        userDetailsService.signUp(user);

        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        
        try {
            response.getWriter().print(CommonUtils.generateAlertMessage(DEFAULT_EMAIL_AUTHENTICATION_MESSAGE));
            response.flushBuffer();
        } catch (IOException e) {
            IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, e.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
        }
    }


    @GetMapping("/email-verification")
    @Transactional
    public String verifyEmail(@RequestParam(name = "email_token") @NotNull String token, Model model) {
        // 이메일 토큰 조회
        EmailToken emailToken = emailTokenService.findByIdAndExpirationDateAfterAndExpired(token);

        if(emailToken.isExpired()){
            IdpError error = CommonUtils.generateError(IdpStatus.ALREADY_AUTHENTICATION_EMAIL);
            throw new IdpApiException(error);
        }

        if(LocalDateTime.now().isAfter(emailToken.getExpirationDate())){
            IdpStatus customStatus = IdpStatus.of(HttpStatus.BAD_REQUEST, "Expired token." + emailToken.getExpirationDate());
            IdpError error = CommonUtils.generateError(customStatus);
            throw new IdpApiException(error);
        }
        
        IdpUser idpUser = (IdpUser)userDetailsService.loadUserByUsername(emailToken.getUsername());

        // 사용 완료 후 불필요한 토큰 삭제 및 사용자 업데이트
        emailToken.setExpired(true);
        emailTokenService.save(emailToken);

        idpUser.setValidEmail(true);
        idpUser.setEnabled(true);
        userDetailsService.save(idpUser);

        return "signup_result";
    }

    /**
     * Oauth2.0용
     * 
     * @param claims
     * @param request
     * @param response
     * @return
     * @throws IOException
     */
    @PostMapping(value = "/clients", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> clients(@RequestParam("client_name") String clientName,
            @RequestParam("redirect_uris") List<String> redirectUris) throws IOException {
        OidcClientRegistration clientRegistration = oauth2Service.convertOidcClientRegistration(clientName,
                redirectUris);
        Jwt jwtAssertion = oauth2Service.createJwt();

        ResponseEntity<String> tokenResponse = this.webClient.post()
                .uri(oauth2ConstantsConfig.getIdpBaseUrl().concat(Oauth2ConstantsConfig.DEFAULT_TOKEN_ENDPOINT_URI))
                .body(BodyInserters
                        .fromFormData(IdpParameterNames.GRANT_TYPE,
                                AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                        .with(IdpParameterNames.SCOPE, Oauth2ConstantsConfig.CLIENT_REGISTRATION_SCOPE)
                        .with(IdpParameterNames.CLIENT_ASSERTION_TYPE, Oauth2ConstantsConfig.DEFAULT_CLIENT_ASSERTION_TYPE)
                        .with(IdpParameterNames.CLIENT_ASSERTION, jwtAssertion.getTokenValue())
                        .with(IdpParameterNames.CLIENT_ID, jwtAssertion.getSubject()))
                .retrieve()
                .toEntity(String.class)
                .block();

        Oauth2Token ouath2Token = gson.fromJson(tokenResponse.getBody(), Oauth2Token.class);

        OAuth2Authorization authorization = oauth2Service.findByToken(ouath2Token);
        if (Objects.isNull(authorization)) {
            IdpError error = CommonUtils.generateError(IdpStatus.INVALID_OAUTH2_TOKEN_NULL);
            throw new IdpApiException(error);
        }
        
        OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();  
        if (!authorizedAccessToken.isActive()) {
            IdpError error = CommonUtils.generateError(IdpStatus.INVALID_OAUTH2_TOKEN);
            throw new IdpApiException(error);
        }

        String secretKey = Oauth2ClientService.CLIENT_SECRET_GENERATOR.generateKey();

        RegisteredClient registeredClient = oauth2Service.registerClient(clientRegistration, secretKey);

        JwtAuthenticationToken authentication = new JwtAuthenticationToken(jwtAssertion,
                AuthorityUtils.createAuthorityList("SCOPE_client.create"));

        OAuth2Authorization registeredClientAuthorization = oauth2Service.registerAccessToken(registeredClient,
                authentication);

        OidcClientRegistration client = oauth2Service.buildRegistration(registeredClient)
                .registrationAccessToken(registeredClientAuthorization.getAccessToken().getToken().getTokenValue())
                .build();

        Map<String, Object> newClaims = new LinkedHashMap<String, Object>(client.getClaims());
        newClaims.put(OidcClientMetadataClaimNames.CLIENT_SECRET, secretKey);

        String exportJson = gson.newBuilder()
                .setPrettyPrinting()
                .create()
                .toJson(newClaims);

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                .withZone(ZoneId.systemDefault());

        String fileName = CommonUtils.generateFileName((String) newClaims.get(OidcClientMetadataClaimNames.CLIENT_NAME),
                (String) newClaims.get(OidcClientMetadataClaimNames.CLIENT_ID), formatter.format(Instant.now()));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=".concat(fileName))
                .contentType(MediaType.APPLICATION_JSON)
                .contentLength(exportJson.length())
                .body(exportJson);
    }

    /**
     * Oauth2.1용
     * 
     * @param claims
     * @param request
     * @param response
     * @return
     * @throws IOException
     */
    @PostMapping(value = "/client", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> client(@RequestParam("client_name") String clientName
            , @RequestParam("redirect_uris") List<String> redirectUris
            , HttpServletResponse response) throws IOException {
        OidcClientRegistration clientRegistration = oauth2Service.convertOidcClientRegistration(clientName,
                redirectUris);

        Jwt jwtAssertion = oauth2Service.createJwt();
        
        ResponseEntity<String> tokenResponse = this.webClient.post()
                .uri(oauth2ConstantsConfig.getIdpBaseUrl().concat(Oauth2ConstantsConfig.DEFAULT_TOKEN_ENDPOINT_URI))
                .body(BodyInserters
                        .fromFormData(IdpParameterNames.GRANT_TYPE,
                                AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                        .with(IdpParameterNames.SCOPE, Oauth2ConstantsConfig.CLIENT_REGISTRATION_SCOPE)
                        .with(IdpParameterNames.CLIENT_ASSERTION_TYPE, Oauth2ConstantsConfig.DEFAULT_CLIENT_ASSERTION_TYPE)
                        .with(IdpParameterNames.CLIENT_ASSERTION, jwtAssertion.getTokenValue())
                        .with(IdpParameterNames.CLIENT_ID, jwtAssertion.getSubject()))
                .retrieve()
                .toEntity(String.class)
                .block();

        Oauth2Token ouath2Token = gson.fromJson(tokenResponse.getBody(), Oauth2Token.class);
        String accessTokenValue = ouath2Token.getAccessToken();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(accessTokenValue);
        OidcClient oidcClient = new OidcClient(clientRegistration);

        ResponseEntity<String> clientResponse = this.webClient.mutate().build()
                .post()
                .uri(oauth2ConstantsConfig.getIdpBaseUrl().concat(Oauth2ConstantsConfig.DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI))
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> {
                    headers.addAll(httpHeaders);
                })
                .body(BodyInserters.fromValue(oidcClient.getClaims()))
                .retrieve()
                .toEntity(String.class)
                .block();
        
        if(clientResponse.getStatusCode().isError()){
            return clientResponse;
        }
        
        Map<String, Object> claims = gson.fromJson(clientResponse.getBody(), Map.class);
        String exportJson = gson.newBuilder()
                .setPrettyPrinting()
                .create()
                .toJson(claims);

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                .withZone(ZoneId.systemDefault());

        String fileName = CommonUtils.generateFileName((String) claims.get(OidcClientMetadataClaimNames.CLIENT_NAME),
                (String) claims.get(OidcClientMetadataClaimNames.CLIENT_ID), formatter.format(Instant.now()));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=".concat(fileName))
                .contentType(MediaType.APPLICATION_JSON)
                .contentLength(exportJson.length())
                .body(exportJson);
    }
}
