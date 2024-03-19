package com.idp.common.util;

import org.springframework.http.HttpStatus;

import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;

public class CommonUtils {
    private CommonUtils() {}

    public static String generateFileName(String... params) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < params.length; i++) {
            sb.append(params[i]);
            if (i < params.length - 1) {
                sb.append("_");
            }
        }
        sb.append(".json");

        return sb.toString();
    }

    public static IdpError generateError(IdpStatus idpStatus) {
        String errorDescription = idpStatus.getMessage();

        HttpStatus status = idpStatus.getHttpStatus();
        int errorCode = status.value();
        String error = status.getReasonPhrase();
        IdpError idpError = new IdpError(error, errorDescription);
        idpError.setErrorCode(errorCode);
        return idpError;
    }

    public static String generateAlertMessage(String alertMessage){
        StringBuffer sb = new StringBuffer();
        sb.append("<script type='text/javascript'>");
        sb.append("alert('" + alertMessage + "');");
        sb.append("location.href = '/'");
        sb.append("</script>");
        
        return sb.toString();
    }
}