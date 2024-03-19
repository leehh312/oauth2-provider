package com.idp.repository.federated;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Repository;

@Repository
// FIXME leehh312 2022.08.31 연합 정보 저장 필요성이 있을 시 DB로 연동 진행
public class FederatedIdentityOAuth2UserRepository {
    private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

    public OAuth2User findByName(String name) {
        return this.userCache.get(name);
    }

    public void save(OAuth2User oauth2User) {
        this.userCache.put(oauth2User.getName(), oauth2User);
    }
}
