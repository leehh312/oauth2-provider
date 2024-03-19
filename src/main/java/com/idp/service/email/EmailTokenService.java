package com.idp.service.email;

import java.time.LocalDateTime;
import java.util.Optional;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import com.nimbusds.jose.util.StandardCharset;
import com.idp.common.IdpStatus;
import com.idp.common.config.security.Oauth2ConstantsConfig;
import com.idp.common.dto.IdpError;
import com.idp.common.dto.entity.EmailToken;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;
import com.idp.repository.email.EmailTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailTokenService {
    // 이메일 토큰 만료 시간
    private static final long DEFAULT_EMAIL_TOKEN_EXPIRATION_TIME = 7L;

	private final Oauth2ConstantsConfig oauth2ConstantsConfig;
	private final EmailSenderService emailSenderService;
	private final EmailTokenRepository emailTokenRepository;
	private final SpringTemplateEngine templateEngine;

	// 이메일 인증 토큰 생성
	public void createEmailToken(String username, String receiverEmail) {
        if(!StringUtils.hasText(username)){
            IdpError error = CommonUtils.generateError(IdpStatus.NULL_EMAIL_MEMBER_ID);
            throw new IdpApiException(error);
        }

        if(!StringUtils.hasText(receiverEmail)){
            IdpError error = CommonUtils.generateError(IdpStatus.NULL_EMAIL_RECEIVE_EMAIL);
            throw new IdpApiException(error);
        }
        
		// 이메일 토큰 저장
		EmailToken emailToken = createEmailToken(username);

		emailTokenRepository.save(emailToken);

		// 이메일 전송
		MimeMessage mailMessage = generateMimeMessageHelper(emailToken.getId(), receiverEmail);

		emailSenderService.sendEmail(mailMessage);
	}

	// 유효한 토큰 가져오기
	public EmailToken findByIdAndExpirationDateAfterAndExpired(String emailTokenId) {
		Optional<EmailToken> emailToken = emailTokenRepository.findById(emailTokenId);
		
		// 토큰이 없다면 예외 발생
		return emailToken.orElseThrow(() ->
            new IdpApiException(CommonUtils.generateError(IdpStatus.INVALID_EMAIL_TOKEN_NULL))
        );
	}

	public void delete(EmailToken emailToken) {
		emailTokenRepository.delete(emailToken);
	}

	public void save(EmailToken emailToken) {
		emailTokenRepository.save(emailToken);
	}

    private EmailToken createEmailToken(String username) {
        LocalDateTime expirationDate = LocalDateTime.now().plusDays(DEFAULT_EMAIL_TOKEN_EXPIRATION_TIME);
		EmailToken token = new EmailToken();
		token.setUsername(username);
		token.setExpirationDate(expirationDate);
		token.setExpired(false);

		return token;
	}

	private MimeMessage generateMimeMessageHelper(String email_token, String email) {
		MimeMessage mimeMessage = emailSenderService.getMimeMessage();
		MimeMessageHelper helper;
		try {
			helper = new MimeMessageHelper(mimeMessage, true, StandardCharset.UTF_8.name());
			helper.addTo(email);
			helper.setSubject("leehh312 IDP 회원 메일 인증");
			helper.setText(getEmailHtmlFile(email_token), true);

			return mimeMessage;
		} catch (MessagingException e) {
			IdpStatus status = IdpStatus.of(HttpStatus.INTERNAL_SERVER_ERROR, e.getLocalizedMessage());
			IdpError error = CommonUtils.generateError(status);
            throw new IdpApiException(error);
		}
	}

	private String getEmailHtmlFile(String email_token){
		String checkValidToken = String.format("%s/email-verification?email_token=%s",oauth2ConstantsConfig.getIdpBaseUrl(), email_token);
		Context context = new Context();
		context.setVariable("checkValidToken", checkValidToken);
		context.setVariable("expiredDays", DEFAULT_EMAIL_TOKEN_EXPIRATION_TIME);
		
		return templateEngine.process("mail_authentication", context);
	}
}
