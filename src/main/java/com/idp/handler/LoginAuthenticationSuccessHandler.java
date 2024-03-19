package com.idp.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import com.idp.common.config.security.Oauth2ConstantsConfig;
import com.idp.common.dto.entity.IdpUser;
import com.idp.service.JpaUserDetailsService;

public class LoginAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final JpaUserDetailsService userDetailsService;

    private final Oauth2ConstantsConfig oauth2ConstantsConfig;

    public LoginAuthenticationSuccessHandler(JpaUserDetailsService jpaUserDetailsService
            , Oauth2ConstantsConfig oauth2ConstantsConfig
            , String DefaultSuccessUrl) {
        this.userDetailsService = jpaUserDetailsService;
        this.oauth2ConstantsConfig = oauth2ConstantsConfig;
        setDefaultTargetUrl(DefaultSuccessUrl);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {  

        // 로그인 시도 횟수 초기화
        if (authentication.getPrincipal() instanceof IdpUser) {
            IdpUser idpUser = (IdpUser) authentication.getPrincipal();
            idpUser.setAccountRemainingCount(oauth2ConstantsConfig.getRemainingCount());

            userDetailsService.save(idpUser);
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

}
