package com.idp.handler.error;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.idp.common.util.CommonUtils;

public class UserSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy{
    private final SessionRegistry sessionRegistry;
    private final static String DEFAULT_ALERT_MESSAGE = "동일 계정이 다른 곳에서 로그인 되었습니다. 자동 로그아웃 됩니다.";
    
    public UserSessionInformationExpiredStrategy(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        sessionRegistry.removeSessionInformation(event.getSessionInformation().getSessionId());
        HttpServletResponse response = event.getResponse();

        response.setContentType("text/html;");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().print(CommonUtils.generateAlertMessage(DEFAULT_ALERT_MESSAGE));
        response.flushBuffer();
    }
}
