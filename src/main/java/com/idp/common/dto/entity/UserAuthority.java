package com.idp.common.dto.entity;

import javax.persistence.CascadeType;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.idp.common.dto.entity.id.UserAuthorityId;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name = "authorities")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserAuthority {
    @EmbeddedId
    private UserAuthorityId userAuthorityId;

    @ManyToOne(cascade = CascadeType.PERSIST)
    @MapsId("username")
    private IdpUser users;
}
