package com.idp.common.dto;

import com.google.gson.annotations.SerializedName;
import com.idp.common.IdpParameterNames;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@RequiredArgsConstructor
public class IdpError {
    // 오류가 발생에 대한 여부
    @SerializedName(value = "error_status")
    private boolean errorStatus = true;

    // 발생하는 오류 유형을 분류하는 데 사용할 수 있고 오류에 대응하는 데 사용할 수 있는 오류 코드 문자열
    @SerializedName(value = IdpParameterNames.ERROR)
    @NonNull
    private String error;

    // 개발자(전용)가 인증 오류의 원인을 식별하도록 도울 수 있는 특정 오류 메시지
    @SerializedName(value = IdpParameterNames.ERROR_DESCRIPTION)
    @NonNull
    private String errorDescription;

    // 개발자(전용)가 어떤 요청에서 에러가 발생 하였는지 식별할 수 있는 URI 
    // 모든 오류에 대해서 제공되지는 않음.
    @SerializedName(value = IdpParameterNames.ERROR_URI)
    @Setter
    private String errorUri;
 
    // 버그 원인에 도움이 될 수 있는 특정 오류 코드 
    // 모든 오류에 대해서 제공되지는 않음.
    @SerializedName(value = "error_code")
    @Setter
    private int errorCode;
}