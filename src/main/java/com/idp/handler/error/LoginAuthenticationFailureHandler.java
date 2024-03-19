package com.idp.handler.error;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import com.idp.common.IdpParameterNames;
import com.idp.common.dto.entity.IdpUser;
import com.idp.service.JpaUserDetailsService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {
      private final JpaUserDetailsService userDetailsService;

      public LoginAuthenticationFailureHandler(JpaUserDetailsService jpaUserDetailsService) {
            this.userDetailsService = jpaUserDetailsService;
      }

      @Override
      @Transactional
      public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                  AuthenticationException exception) throws IOException, ServletException {
            String reqPath = request.getRequestURI();
            String meesage;
            int code = HttpStatus.BAD_REQUEST.value();

            String username = request.getParameter(IdpParameterNames.USERNAME);

            /**
             ****** 로그인 에러 종류
             * BadCredentialException
             * 비밀번호가 일치하지 않을 때 던지는 예외
             * 
             * InternalAuthenticationServiceException
             * 존재하지 않는 아이디일 때 던지는 예외
             * 
             * UsernameNotFoundException
             * 존재하지않는 계정으로 로그인 시도하였을 시
             * 
             * AuthenticationCredentialNotFoundException
             * 인증 요구가 거부됐을 때 던지는 예외
             * 
             * LockedException
             * 인증 거부 - 잠긴 계정
             * 
             * DisabledException
             * 인증 거부 - 계정 비활성화
             * 
             * AccountExpiredException
             * 인증 거부 - 계정 유효기간 만료
             * 
             * CredentialExpiredException
             * 인증 거부 - 비밀번호 유효기간 만료
             */
            boolean existsUser = false;
            if (exception instanceof BadCredentialsException) {
                  IdpUser idpUser = (IdpUser) userDetailsService.loadUserByUsername(username);
                  int remainingCount = idpUser.getAccountRemainingCount();
                  if (remainingCount > 0) {
                        remainingCount = idpUser.getAccountRemainingCount() - 1;
                        idpUser.setAccountRemainingCount(remainingCount);

                        if (remainingCount == 0)
                              idpUser.setAccountNonLocked(false);
                  }

                  userDetailsService.save(idpUser);

                  meesage = "비밀번호가 맞지 않습니다. 남은횟수: " + remainingCount;
            } else if (exception instanceof InternalAuthenticationServiceException) {
                  meesage = "내부 시스템 문제로 로그인 요청을 처리할 수 없습니다. 관리자에게 문의하세요.";
            } else if (exception instanceof UsernameNotFoundException) {
                  meesage = "존재하지 않는 계정입니다. 회원가입 후 로그인해주세요.";
            } else if (exception instanceof AuthenticationCredentialsNotFoundException) {
                  meesage = "인증 요청이 거부되었습니다. 관리자에게 문의하세요.";
            } else if (exception instanceof LockedException) {
                  meesage = "계정이 잠겨있습니다. 비밀번호 찾기를 통하여 변경 바랍니다.";
            } else if (exception instanceof SessionAuthenticationException) {
                  meesage = "이미 접속한 계정입니다.";
                  existsUser = true;
            } else if (exception instanceof DisabledException) {
                  meesage = "비활성화된 계정입니다. 회원가입 시 이메일 인증하지 않았는지 확인 하시거나 혹은 관리자에게 문의바랍니다.";
            }else {
                  meesage = "알 수 없는 오류로 로그인 요청을 처리할 수 없습니다. 관리자에게 문의하세요.";
            }
            
            String error_description = URLEncoder.encode(meesage, StandardCharsets.UTF_8.name()).replaceAll("\\+",
                        "%20");
            String url;
            if(existsUser){
                url = "/login?error=true&exists_user=true&error_description=" + error_description;
            }else{
                url = "/login?error=true&error_description=" + error_description;
            }

            request.getRequestDispatcher(url).forward(request, response);

            log.error("error_code: {}, error_description: {}, error_request_path : {}", code, meesage,
                        reqPath, exception);
      }
}
