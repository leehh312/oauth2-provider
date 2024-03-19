package com.idp.common.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;

import org.springframework.format.datetime.DateFormatter;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public final class Jwks {
	private Jwks() {}

	public static RSAKey getRsa(File file, String alias, String password) {
		KeyStore clientStore;

		try {
			clientStore = KeyStore.getInstance("PKCS12");
			clientStore.load(new FileInputStream(file), password.toCharArray());
			return RSAKey.load(clientStore, alias, password.toCharArray());
		} catch (KeyStoreException
				| NoSuchAlgorithmException
				| CertificateException
				| IOException
				| JOSEException e) {

			IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, e.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
		}
	}

	public static RSAKey generateRsa() {
		KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	public static OctetSequenceKey generateSecret() {
		SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();
		return new OctetSequenceKey.Builder(secretKey)
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	public static String generateClientSecret(String clientId) {
		DateFormatter dateFormatter = new DateFormatter("yyyyddMMHHmmss");
		String timestamp = dateFormatter.print(new java.util.Date(), Locale.KOREA);
		String clientSecret = new StringBuffer().append(clientId).append(":").append(timestamp).toString();
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		return UUID.nameUUIDFromBytes(encoder.encode(clientSecret).getBytes(StandardCharsets.UTF_8))
				.toString();
	}

	public static String generateClientId(String clientName) {
		byte[] seed = clientName.getBytes(StandardCharsets.UTF_8);
		return Base64URL.encode(UUID.nameUUIDFromBytes(seed).toString())
				.toString()
				.toLowerCase();
	}
}