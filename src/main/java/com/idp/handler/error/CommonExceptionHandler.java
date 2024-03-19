package com.idp.handler.error;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;

import com.idp.common.IdpParameterNames;
import com.idp.common.dto.IdpError;
import com.idp.common.exception.IdpApiException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
// properties에 server.error.path가 있으면 그 값을 없을경우 error.path를 사용하고 둘다 없는 경우 /error를 맵핑하도록
@RequestMapping("${server.error.path:${error.path:/error}}")
public class CommonExceptionHandler extends BasicErrorController{
	private final ErrorAttributes errorAttributes;
	private final static String DEFAULT_ERROR_PAGE = "error/error";

	public CommonExceptionHandler(ErrorAttributes errorAttributes
								, ServerProperties serverProperties
								, List<ErrorViewResolver> errorViewResolvers) {
		super(errorAttributes, serverProperties.getError(), errorViewResolvers);
		this.errorAttributes = errorAttributes;
	}
	
	// FIXME leehh312 2022.10.18 
	// mvc패턴 방식에서 에러 났을 시 기존 요청하였던 페이지로 리턴할지 아니면 에러페이지 만들어 에러페이지로 리턴할 지 정해야할 부분
	@RequestMapping(produces = MediaType.TEXT_HTML_VALUE)
	public ModelAndView errorHtml(HttpServletRequest request, HttpServletResponse response) {
		Map<String, Object> attributes = getErrorAttributes(request, getErrorAttributeOptions(request, MediaType.TEXT_HTML));

		Integer errorCode =  (Integer)attributes.get("status");
		String error =  (String)attributes.get("error");
		String errorUri = (String)attributes.get("path");
		WebRequest webRequest = new ServletWebRequest(request, response);
		Throwable throwable = errorAttributes.getError(webRequest);
		String errorDescription = throwable.getLocalizedMessage();
		
		if(throwable instanceof IdpApiException){
			IdpApiException exception = (IdpApiException)throwable;
			IdpError idpError = exception.getIdpError();
			// HTTP 상태코드 
			errorCode = idpError.getErrorCode();

			// HTTP 에러메시지
			error = idpError.getError();

			// 서버 디테일 메시지
			errorDescription = idpError.getErrorDescription();

			// Ouath2규격맞게 ErrorUri에 Oauth2 에러 참고 링크 uri 있을 시 진행
			if(StringUtils.hasText(idpError.getErrorUri())){
				errorUri = idpError.getErrorUri();
			}
		// NullPointerException발생 시 담겨있는 message자체가 null이기 때문에 발생한 위치 추적가능한 에러자체를 errorDescription에 담아서 반환
		}else if(throwable instanceof NullPointerException){
			StringWriter sw = new StringWriter();
    		PrintWriter pw = new PrintWriter(sw);
			throwable.printStackTrace(pw);

			errorDescription = sw.toString();
		}

		attributes.clear();
		attributes.put(IdpParameterNames.ERROR_CODE, errorCode);
		attributes.put(IdpParameterNames.ERROR, error);
		attributes.put(IdpParameterNames.ERROR_DESCRIPTION, errorDescription);
		attributes.put(IdpParameterNames.ERROR_URI, errorUri);
		
		ModelAndView modelAndView = resolveErrorView(request, response, HttpStatus.valueOf(errorCode), attributes);

		log(errorCode, error, errorDescription, errorUri, throwable);

		return (modelAndView != null) ? modelAndView : new ModelAndView(DEFAULT_ERROR_PAGE, attributes);
	}

	@Override
	public ResponseEntity<Map<String, Object>> error(HttpServletRequest request) {
		HttpStatus status = getStatus(request);
		if (status == HttpStatus.NO_CONTENT) {
			return new ResponseEntity<>(status);
		}
		
		Map<String, Object> attributes = getErrorAttributes(request, getErrorAttributeOptions(request, MediaType.ALL));
		attributes.clear();

		attributes.put(IdpParameterNames.ERROR_CODE, (Integer)attributes.get("status"));
		attributes.put(IdpParameterNames.ERROR, (String)attributes.get("error"));
		attributes.put(IdpParameterNames.ERROR_URI, (String)attributes.get("path"));
		WebRequest webRequest = new ServletWebRequest(request);
		Throwable throwable = errorAttributes.getError(webRequest);
		String errorDescription = throwable.getLocalizedMessage();
		attributes.put(IdpParameterNames.ERROR_DESCRIPTION, errorDescription);

		if(throwable instanceof IdpApiException){
			IdpApiException exception = (IdpApiException)throwable;
			IdpError idpError = exception.getIdpError();
			// HTTP 상태코드 
			attributes.put(IdpParameterNames.ERROR_CODE, idpError.getErrorCode());
			status = HttpStatus.valueOf(idpError.getErrorCode());

			// HTTP 에러메시지
			attributes.put(IdpParameterNames.ERROR, idpError.getError());

			// 서버 디테일 메시지
			attributes.put(IdpParameterNames.ERROR_DESCRIPTION, idpError.getErrorDescription());
			
			// Ouath2규격맞게 ErrorUri에 Oauth2 에러 참고 링크 uri 있을 시 진행
			if(StringUtils.hasText(idpError.getErrorUri())){
				attributes.put(IdpParameterNames.ERROR_URI, idpError.getErrorUri());
			}
		// NullPointerException발생 시 담겨있는 message자체가 null이기 때문에 발생한 위치 추적가능한 에러자체를 errorDescription에 담아서 반환
		}else if(throwable instanceof NullPointerException){
			StringWriter sw = new StringWriter();
    		PrintWriter pw = new PrintWriter(sw);
			throwable.printStackTrace(pw);

			attributes.put(IdpParameterNames.ERROR_DESCRIPTION, sw.toString());
		}

		log(attributes, throwable);

		return new ResponseEntity<>(attributes, status);
	}

	private void log(Integer errorCode, String error, String errorDescription, String errorUri, Throwable throwable) {
		log.error("{}: {}, {}: {}, {}: {}, {}: {}"
				, IdpParameterNames.ERROR_CODE, errorCode
                , IdpParameterNames.ERROR, error
                , IdpParameterNames.ERROR_DESCRIPTION, errorDescription
                , IdpParameterNames.ERROR_URI, errorUri
				, throwable);
	}

	private void log(Map<String, Object> attributes, Throwable throwable) {
		log.error(attributes.toString(), throwable);
	}
}
