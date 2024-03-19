package com.idp.repository.email;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import com.idp.common.dto.entity.EmailToken;

@Transactional(readOnly = true)
public interface EmailTokenRepository extends JpaRepository<EmailToken, String> {}
