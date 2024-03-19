package com.idp.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.stereotype.Repository;

@Repository
public class Oauth2ClientRepository extends JdbcRegisteredClientRepository {

    public Oauth2ClientRepository(JdbcTemplate jdbcTemplate) {
        super(jdbcTemplate);
    }
}
