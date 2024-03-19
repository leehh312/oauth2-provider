package com.idp.common.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;

@Configuration
@Getter
public class Oauth2ConstantsConfig {
    private final String provider_issue_url;

    private final String oauth2PfxPath;

    private final String oauth2PfxAlias;

    private final String oauth2PfxPass;

    private final String rememberKeyname;

    private final String idpBaseUrl;
        
    private final int remainingCount;

    public final static String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

    public final static String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";

    public final static String CLIENT_REGISTRATION_SCOPE = "client.create";

    public final static String DEFAULT_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public final static String MORPHEUS_IDP_LOGINPAGE = "/login";

    public final static String MORPHEUS_IDP_LOGOUTPAGE = "/logout";

    public final static String DEFAULT_SUCCESS_URL = "/";

    public final static String[] AUTHENTICATION_IGNORE_URL = {
        "/assets/**"
        , "/webjars/**"
        , "/"
        , "/login"
        , "/error"
        , "/signup"
        , "/login/force"
        , "/expired"
        , "/email-verification"
    };

    public Oauth2ConstantsConfig(@Value("${idp.oauth2.provider-url}") String provider_issue_url
            , @Value("${idp.oauth2.pfx.path}") String oauth2PfxPath
            , @Value("${idp.oauth2.pfx.alias}") String oauth2PfxAlias
            , @Value("${idp.oauth2.pfx.password}") String oauth2PfxPass
            , @Value("${idp.oauth2.remember.key-name}") String rememberKeyname
            , @Value("${idp.oauth2.provider-url}") String idpBaseUrl
            , @Value("${idp.oauth2.login.remaining-count}") int remainingCount) {
        this.provider_issue_url = provider_issue_url;
        this.oauth2PfxPath = oauth2PfxPath;
        this.oauth2PfxAlias = oauth2PfxAlias;
        this.oauth2PfxPass = oauth2PfxPass;
        this.rememberKeyname = rememberKeyname;
        this.idpBaseUrl = idpBaseUrl;
        this.remainingCount = remainingCount;
    }
}
