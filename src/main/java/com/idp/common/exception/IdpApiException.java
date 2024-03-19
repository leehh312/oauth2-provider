package com.idp.common.exception;

import java.util.Objects;

import com.idp.common.dto.IdpError;

/**
 * idp Custom Exception
 * 
 * @author leehh312
 */
public class IdpApiException extends RuntimeException {
	private static final long serialVersionUID = 1L;
	private final IdpError error;

	public IdpApiException(IdpError error) {
		super(error.getErrorDescription());
		this.error = error;
	}

	public IdpError getIdpError() {
		return this.error;
	}

	public boolean isExistsIdpError() {
		return Objects.nonNull(this.error);
	}
}
