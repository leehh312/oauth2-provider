package com.idp.common.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.http.HttpStatus;

import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;

public class PkceGeneratorUtils {
    private PkceGeneratorUtils() {
    }

    public static String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    public static String generateCodeChallange(String codeVerifier) {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.UTF_8);
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes, 0, bytes.length);
            byte[] digest = messageDigest.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, e.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
        }
    }
}
