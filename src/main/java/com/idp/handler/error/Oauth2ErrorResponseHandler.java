package com.idp.handler.error;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;

import com.google.gson.Gson;
import com.idp.common.IdpParameterNames;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Oauth2ErrorResponseHandler implements AuthenticationFailureHandler{
    private Gson gson;

    public Oauth2ErrorResponseHandler(Gson gson) {
        this.gson = gson;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        OAuth2Error ouath2Error = ((OAuth2AuthenticationException) exception).getError();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        if(!StringUtils.hasText(ouath2Error.getUri())){
            String reqPath = String.valueOf(request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI));
            reqPath = StringUtils.hasText(ouath2Error.getUri()) ? reqPath : request.getRequestURI();    
            ouath2Error = new OAuth2Error(ouath2Error.getErrorCode(), ouath2Error.getDescription(), reqPath);
        }
        
        response.getWriter().write(gson.toJson(ouath2Error));

        log.error("{}: {}, {}: {}, {}: {}"
                , IdpParameterNames.ERROR, ouath2Error.getErrorCode()
                , IdpParameterNames.ERROR_DESCRIPTION, ouath2Error.getDescription()
                , IdpParameterNames.ERROR_URI, ouath2Error.getUri()
                , exception);
    }
}
