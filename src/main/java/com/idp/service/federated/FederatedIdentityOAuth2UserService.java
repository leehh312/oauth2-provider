package com.idp.service.federated;

import java.util.function.Consumer;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.idp.repository.federated.FederatedIdentityOAuth2UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public final class FederatedIdentityOAuth2UserService implements Consumer<OAuth2User> {

	private final FederatedIdentityOAuth2UserRepository userRepository;

	@Override
	public void accept(OAuth2User user) {
		if (this.userRepository.findByName(user.getName()) == null) {
			if(log.isDebugEnabled()){
				log.debug("Saving first-time user: name={}, claims={}, authorities={}", user.getName(), user.getAttributes(), user.getAuthorities());
			}
			this.userRepository.save(user);
		}
	}
}
