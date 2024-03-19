package com.idp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.EntityGraph.EntityGraphType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.idp.common.dto.entity.IdpUser;

@Repository
public interface UserDetailsRepository extends JpaRepository<IdpUser, String> {
	@EntityGraph(attributePaths = { "userAuthorityList" }, type = EntityGraphType.LOAD)
	@Override
	Optional<IdpUser> findById(String id);

	@Query(value = "SELECT * FROM users WHERE email = ?1", nativeQuery = true)
	Optional<IdpUser> existsEmail(String email);
}
