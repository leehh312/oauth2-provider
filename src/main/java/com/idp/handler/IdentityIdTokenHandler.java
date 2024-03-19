package com.idp.handler;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.idp.common.IdpParameterNames;
import com.idp.common.dto.entity.IdpUser;

public final class IdentityIdTokenHandler implements OAuth2TokenCustomizer<JwtEncodingContext> {
	private Function<JwtEncodingContext, Map<String, Object>> userInfoMapper = new DefaultOidcUserInfoMapper();

	private static final Set<String> ID_TOKEN_CLAIMS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
			IdTokenClaimNames.ISS,
			IdTokenClaimNames.SUB,
			IdTokenClaimNames.AUD,
			IdTokenClaimNames.EXP,
			IdTokenClaimNames.IAT,
			IdTokenClaimNames.AUTH_TIME,
			IdTokenClaimNames.NONCE,
			IdTokenClaimNames.ACR,
			IdTokenClaimNames.AMR,
			IdTokenClaimNames.AZP,
			IdTokenClaimNames.AT_HASH,
			IdTokenClaimNames.C_HASH)));

	@Override
	public void customize(JwtEncodingContext context) {
		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			Map<String, Object> thirdPartyClaims = extractClaims(context);
			
			// 중복 체크 및 제거
			context.getClaims().claims(existingClaims -> {
				existingClaims.keySet().forEach(thirdPartyClaims::remove);
				ID_TOKEN_CLAIMS.forEach(thirdPartyClaims::remove);
				existingClaims.putAll(thirdPartyClaims);
			});
		}
	}

	private Map<String, Object> extractClaims(JwtEncodingContext context) {
		Map<String, Object> claims = new HashMap<>();
		Authentication authentication = context.getPrincipal();
		if (authentication.getPrincipal() instanceof OidcUser) {
			OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
			OidcIdToken idToken = oidcUser.getIdToken();
			claims.putAll(idToken.getClaims());
			claims.put(StandardClaimNames.PREFERRED_USERNAME, oidcUser.getName());
		} 
		else if (authentication.getPrincipal() instanceof OAuth2User) {
			OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
			claims.putAll(oauth2User.getAttributes());
			claims.put(StandardClaimNames.PREFERRED_USERNAME, oauth2User.getName());
		}
		// IdpUser일 경우 
		else {
			claims = userInfoMapper.apply(context);
		}
		
		return claims;
	}

	private static final class DefaultOidcUserInfoMapper implements Function<JwtEncodingContext, Map<String, Object>> {
		private static final List<String> EMAIL_CLAIMS = Arrays.asList(
				StandardClaimNames.EMAIL,
				StandardClaimNames.EMAIL_VERIFIED
		);

		private static final List<String> PHONE_CLAIMS = Arrays.asList(
				StandardClaimNames.PHONE_NUMBER,
				StandardClaimNames.PHONE_NUMBER_VERIFIED
		);

		private static final List<String> PROFILE_CLAIMS = Arrays.asList(
				StandardClaimNames.NAME,
				StandardClaimNames.FAMILY_NAME,
				StandardClaimNames.GIVEN_NAME,
				StandardClaimNames.MIDDLE_NAME,
				StandardClaimNames.NICKNAME,
				StandardClaimNames.PREFERRED_USERNAME,
				StandardClaimNames.PROFILE,
				StandardClaimNames.PICTURE,
				StandardClaimNames.WEBSITE,
				StandardClaimNames.GENDER,
				StandardClaimNames.BIRTHDATE,
				StandardClaimNames.ZONEINFO,
				StandardClaimNames.LOCALE,
				StandardClaimNames.UPDATED_AT
		);

		@Override
		public Map<String, Object> apply(JwtEncodingContext authenticationContext) {
			IdpUser user = (IdpUser) authenticationContext.getPrincipal().getPrincipal();
			Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(user, authenticationContext.getAuthorizedScopes());
			
			return scopeRequestedClaims;
		}

		private static Map<String, Object> getClaimsRequestedByScope(IdpUser user, Set<String> requestedScopes) {
			Set<String> scopeRequestedClaimNames = new HashSet<>(32);
			scopeRequestedClaimNames.add(StandardClaimNames.SUB);

			if (requestedScopes.contains(OidcScopes.ADDRESS)) {
				scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
			}
			if (requestedScopes.contains(OidcScopes.EMAIL)) {
				scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
			}
			if (requestedScopes.contains(OidcScopes.PHONE)) {
				scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
			}
			if (requestedScopes.contains(OidcScopes.PROFILE)) {
				scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
			}

			Map<String, Object> requestedClaims = convertFrom(user);
			requestedClaims.keySet().removeIf(claimName -> !scopeRequestedClaimNames.contains(claimName));

			return requestedClaims;
		}

		private static Map<String, Object> convertFrom(IdpUser idpUser) {
			Map<String, Object> claims = new HashMap<>();
			claims.put(IdpParameterNames.USERNAME, idpUser.getUsername());
			claims.put(StandardClaimNames.PREFERRED_USERNAME, idpUser.getPreferredUsername());
			claims.put(StandardClaimNames.FAMILY_NAME, idpUser.getFamilyName());
			claims.put(StandardClaimNames.GIVEN_NAME, idpUser.getGivenName());
			claims.put(StandardClaimNames.NAME, idpUser.getName());
			claims.put(StandardClaimNames.PHONE_NUMBER, idpUser.getPhoneNumber());
			claims.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, idpUser.isValidPhoneNumber());
			claims.put(StandardClaimNames.EMAIL, idpUser.getEmail());
			claims.put(StandardClaimNames.EMAIL_VERIFIED, idpUser.isValidEmail());
			claims.put(StandardClaimNames.BIRTHDATE, idpUser.getBirthdate());
			claims.put(StandardClaimNames.GENDER, idpUser.getGender());
			claims.put(StandardClaimNames.ADDRESS, idpUser.getAddress());
			claims.put(StandardClaimNames.UPDATED_AT, idpUser.getUpdatedAt().toString());
	
			List<String> authorities_list = new ArrayList<>();
			idpUser.getAuthorities().forEach((grantedAuthority) -> {
				authorities_list.add(grantedAuthority.getAuthority());
			});
	
			return claims;
		}
	}
}
