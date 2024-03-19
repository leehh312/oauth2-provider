package com.idp.common;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

public interface IdpParameterNames extends OAuth2ParameterNames{
    String ERROR_STATUS = "error_status";
    String ERROR_CODE = "error_code";
    String EXISTS_USER = "exists_user";
    String ENABLED = "enabled";
    String ACCOUNT_NON_EXPIRED = "account_non_expired";
    String ACCOUNT_NON_LOCKED = "account_non_Locked";
    String CREDENTIALS_NON_EXPIRED = "credentials_non_expired";
    String ACCOUNT_REMAINING_COUNT = "account_remaining_count";
    
}
