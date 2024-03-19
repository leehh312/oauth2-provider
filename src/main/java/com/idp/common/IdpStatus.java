package com.idp.common;

import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;

import lombok.Getter;

@Getter
public enum IdpStatus {
	CUSTOM_ERROR(null, null)
	, NULL_ENCODER(HttpStatus.INTERNAL_SERVER_ERROR, "encoder cannot be null")
	, NULL_LOGIN_PAGE_URL(HttpStatus.INTERNAL_SERVER_ERROR, "login page URL cannot be empty")
	, NULL_FEDERATED_AUTHORIZATION_REQUEST_URI(HttpStatus.INTERNAL_SERVER_ERROR, "authorization request URI cannot be empty")
	, NULL_FEDERATED_OAUTH2_USER_SERVICE(HttpStatus.INTERNAL_SERVER_ERROR, "oauth2 user service cannot be null")
	, NULL_FEDERATED_AUTHENTICATION_FAIL_HANDLER(HttpStatus.INTERNAL_SERVER_ERROR, "authenticationFailureHandler cannot be null")
	, FAIL_GENERATE_ACCESSTOKEN(HttpStatus.INTERNAL_SERVER_ERROR, "The token generator failed to generate the registration access token")
	, NULL_OAUTH2_CLIENT_NAME(HttpStatus.BAD_REQUEST, "client_name cannot be null")
	, INVALID_OAUTH2_REQUEST_URI(HttpStatus.BAD_REQUEST, "request URI value is invalid request")
	, INVALID_JSON_DESEIALIZE_INSTANT(HttpStatus.BAD_REQUEST, "instant cannot deserialize. must be string format")
	, ALREADY_EXISTS_USER(HttpStatus.BAD_REQUEST, "user already exists")
	, INVALID_OAUTH2_TOKEN_NULL(HttpStatus.BAD_REQUEST, "token cannot find from authorization service")
	, INVALID_OAUTH2_TOKEN(HttpStatus.BAD_REQUEST, "token is not available, isActive(): false")
	, NULL_EMAIL_MEMBER_ID(HttpStatus.BAD_REQUEST, "username cannot be null")
	, NULL_EMAIL_RECEIVE_EMAIL(HttpStatus.BAD_REQUEST, "receive email cannot be null")
	, INVALID_EMAIL_TOKEN_NULL(HttpStatus.BAD_REQUEST, "token cannot find from email token service")
	, ALREADY_EXISTS_EMAIL(HttpStatus.BAD_REQUEST, "email already registered exists")
	, ALREADY_AUTHENTICATION_EMAIL(HttpStatus.BAD_REQUEST, "already authenticated by email.");

	private static final IdpStatus[] VALUES;

	static {
		VALUES = values();
	}

	private HttpStatus httpStatus; 
	private String message;

	IdpStatus(HttpStatus httpStatus, String message) {
		this.httpStatus = httpStatus;
		this.message = message;
	}

	private void setHttpStatus(HttpStatus httpStatus) {
		this.httpStatus = httpStatus;
	}

	private void setMessage(String message) {
		this.message = message;
	}

	@Nullable
	public static IdpStatus resolve(String message) {
		for (IdpStatus status : VALUES) {
			if (status.getMessage().equals(message)) {
				return status;
			}
		}

		return null;
	}

	public static IdpStatus of(HttpStatus httpStatus, String message) {
		IdpStatus status = IdpStatus.CUSTOM_ERROR;
		status.setHttpStatus(httpStatus);
		status.setMessage(message);

		return status;
	}
}
