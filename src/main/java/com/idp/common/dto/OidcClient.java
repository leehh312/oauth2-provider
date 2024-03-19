package com.idp.common.dto;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.util.StringUtils;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OidcClient {
    private final Map<String, Object> claims;

    public OidcClient(OidcClientRegistration oidcClientRegistration) {
        this.claims = new LinkedHashMap<>();
        oidcClientRegistration.getClaims().forEach((k, v) -> {
            if (k.equals(OidcClientMetadataClaimNames.SCOPE)) {
                claims.put(k, StringUtils.collectionToCommaDelimitedString(((List<String>) v)));
            } else {
                claims.put(k, v);
            }
        });
    }

}