package com.idp.handler.error;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.google.gson.Gson;
import com.idp.common.IdpParameterNames;
import com.idp.common.config.json.GsonInitializer;
import com.idp.common.dto.IdpError;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Oauth2AccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Gson gson = GsonInitializer.getInstance().getGson();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        int errorCode = Integer.valueOf(String.valueOf(request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE)));
        HttpStatus httpStatus = HttpStatus.valueOf(errorCode);
        String errorUri = String.valueOf(request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI));

        IdpError idpError = new IdpError(httpStatus.getReasonPhrase(), accessDeniedException.getLocalizedMessage());
        idpError.setErrorCode(errorCode);
        idpError.setErrorUri(errorUri);
        
        response.getWriter().write(gson.toJson(idpError));

		log.error("{}: {}, {}: {}, {}: {}, {}: {}"
				, IdpParameterNames.ERROR_CODE, idpError.getErrorCode()
                , IdpParameterNames.ERROR, idpError.getError()
                , IdpParameterNames.ERROR_DESCRIPTION, idpError.getErrorDescription()
                , IdpParameterNames.ERROR_URI, idpError.getErrorUri()
                , accessDeniedException);
    }
}
