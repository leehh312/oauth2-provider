package com.idp.service.email;

import javax.mail.internet.MimeMessage;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailSenderService {

	private final JavaMailSender mailSender;

	@Async
	public void sendEmail(MimeMessage message) {
		mailSender.send(message);
	}

	public MimeMessage getMimeMessage(){
		return mailSender.createMimeMessage();
	}
}
