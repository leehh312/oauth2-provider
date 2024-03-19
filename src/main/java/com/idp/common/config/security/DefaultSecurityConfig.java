package com.idp.common.config.security;

import java.util.function.Consumer;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import com.idp.handler.error.UserSessionInformationExpiredStrategy;
import com.idp.handler.LoginAuthenticationSuccessHandler;
import com.idp.handler.error.LoginAuthenticationFailureHandler;
import com.idp.handler.federated.FederatedIdentityAuthenticationSuccessHandler;
import com.idp.handler.federated.FederatedIdentityConfigurer;
import com.idp.service.JpaUserDetailsService;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http
            , SessionRegistry sessionRegistry
            , FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler
            , LoginAuthenticationFailureHandler loginAuthenticationFailureHandler
            , LoginAuthenticationSuccessHandler loginAuthenticationSuccessHandler
            , UserSessionInformationExpiredStrategy userSessionInformationExpiredStrategy
            , JdbcTokenRepositoryImpl tokenRepository
            , JpaUserDetailsService jpaUserDetailsService
            , Oauth2ConstantsConfig oauth2ConstantsConfig
            , Consumer<OAuth2User> oAuth2UserService
            , CorsConfigurationSource corsConfigurationSource
            , CsrfTokenRepository csrfTokenRepository) throws Exception {

        return http
                .csrf(csrf -> {
                    csrf.csrfTokenRepository(csrfTokenRepository);
                })
                // Default Security Headers
                /**
                 * Cache-Control: no-cache, no-store, max-age=0, must-revalidate
                 * Pragma: no-cache
                 * Expires: 0
                 * X-Content-Type-Options: nosniff
                 * Strict-Transport-Security: max-age=31536000 ; includeSubDomains
                 * X-Frame-Options: DENY
                 * X-XSS-Protection: 1; mode=block
                 */
                .headers((header) -> 
                    header.frameOptions()
                    // X-Frame-Options: DENY -> SAMEORIGIN 
                    .sameOrigin()
                )
                .cors(cors -> {
                    // 다른 도메인(크로스 사이트)간에 Cookie 전달 할 수 있도록 설정
                    cors.configurationSource(corsConfigurationSource);
                })
                .formLogin(login -> 
                    login.failureHandler(loginAuthenticationFailureHandler)
                        .successHandler(loginAuthenticationSuccessHandler)
                )
                .apply(new FederatedIdentityConfigurer().oauth2UserHandler(oAuth2UserService)
                                                    .authenticationFailureHandler(loginAuthenticationFailureHandler)
                ).and()
                .logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher(Oauth2ConstantsConfig.MORPHEUS_IDP_LOGOUTPAGE))
                        .deleteCookies("JSESSIONID", oauth2ConstantsConfig.getRememberKeyname())
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutSuccessUrl(Oauth2ConstantsConfig.DEFAULT_SUCCESS_URL)
                )
                .sessionManagement(session -> 
                    // 인증 성공할 때 새로운 세션 생성
                    // Session Fixation 보안 취약점 보완
                    // Servlet 3.1 이상 부터는 changeSessionId가 기본 설정값
                    session.sessionFixation().changeSessionId()
                        .sessionAuthenticationFailureHandler(loginAuthenticationFailureHandler)
                        // 최대 허용 가능 세션 수
                        .maximumSessions(1)
                        // 동시 로그인 차단
                        .maxSessionsPreventsLogin(true)
                        .sessionRegistry(sessionRegistry)
                        .expiredSessionStrategy(userSessionInformationExpiredStrategy)
                )
                .rememberMe(remember -> 
                    remember.alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행, default: false
                        .useSecureCookie(true)
                        .tokenRepository(tokenRepository)
                        .tokenValiditySeconds(3600) // 쿠키의 만료시간 설정(초), default: 14일
                        .userDetailsService(jpaUserDetailsService)
                        .rememberMeParameter(oauth2ConstantsConfig.getRememberKeyname())
                        .rememberMeCookieName(oauth2ConstantsConfig.getRememberKeyname())
                )
                .authorizeRequests(auth -> {
                    auth.mvcMatchers(Oauth2ConstantsConfig.AUTHENTICATION_IGNORE_URL)
                            .permitAll()
                            .anyRequest().authenticated();
                })
                .build();
    }
}