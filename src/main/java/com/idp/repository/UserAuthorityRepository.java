package com.idp.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.idp.common.dto.entity.UserAuthority;

public interface UserAuthorityRepository extends JpaRepository<UserAuthority, String> {
}
