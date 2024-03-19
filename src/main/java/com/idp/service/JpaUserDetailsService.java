package com.idp.service;

import java.util.Objects;
import java.util.Optional;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.idp.common.IdpStatus;
import com.idp.common.dto.IdpError;
import com.idp.common.dto.entity.IdpUser;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;
import com.idp.repository.UserDetailsRepository;
import com.idp.service.email.EmailTokenService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {
    private final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private final UserDetailsRepository userDetailsRepository;
    private final EmailTokenService emailTokenService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = this.userDetailsRepository.findById(username).orElse(null);
        if (Objects.isNull(userDetails)) {
            throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.notFound",
                    new Object[] { username }, "Username {0} not found"));
        }

        return userDetails;
    }

    public void save(IdpUser idpUser) {
        this.userDetailsRepository.save(idpUser);
    }

    @Transactional
    public void signUp(IdpUser idpUser) {
        if (existsUser(idpUser.getUsername())){
            IdpError error = CommonUtils.generateError(IdpStatus.ALREADY_EXISTS_USER);
            throw new IdpApiException(error);
        }

        if(existsEmail(idpUser.getEmail())){
            IdpError error = CommonUtils.generateError(IdpStatus.ALREADY_EXISTS_EMAIL);
            throw new IdpApiException(error);
        }
        this.userDetailsRepository.save(idpUser);

        emailTokenService.createEmailToken(idpUser.getUsername(), idpUser.getEmail());
    }

    public boolean existsUser(String username) {
        return userDetailsRepository.existsById(username);
    }

    public boolean existsEmail(String email)  {
        Optional<IdpUser> idpUser = this.userDetailsRepository.existsEmail(email);
        if(idpUser.isPresent()){
            return true;
        }

        return false;
    }

}
