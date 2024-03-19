package com.idp.common.dto;

import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Oauth2Token {
    private String scope;
    @SerializedName(value = "token_type")
    private String tokenType;
    @SerializedName(value = "expires_in")
    private String expiresIn;
    @SerializedName(value = "access_token")
    private String accessToken;
}
