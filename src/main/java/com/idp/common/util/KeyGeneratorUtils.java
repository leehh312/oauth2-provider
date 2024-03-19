package com.idp.common.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.http.HttpStatus;

import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;

final class KeyGeneratorUtils {

	private KeyGeneratorUtils() {
	}

	static SecretKey generateSecretKey() {
		SecretKey hmacKey;
		try {
			hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
		} catch (Exception ex) {
			IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, ex.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
		}
		return hmacKey;
	}

	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, ex.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
		}
		return keyPair;
	}
}
