package com.idp.common.dto.entity;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import com.idp.common.IdpParameterNames;
import com.idp.common.IdpStatus;
import com.idp.common.config.json.GsonIgnore;
import com.idp.common.dto.IdpError;
import com.idp.common.dto.UserSignInfo;
import com.idp.common.dto.entity.id.UserAuthorityId;
import com.idp.common.exception.IdpApiException;
import com.idp.common.util.CommonUtils;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Table(name = "users")
@SecondaryTable(name = "authorities", pkJoinColumns = @PrimaryKeyJoinColumn(name = "users_username"))
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonIgnoreProperties(ignoreUnknown = true)
@EqualsAndHashCode(of = "username")
public class IdpUser implements Principal, UserDetails {
    @JsonProperty(StandardClaimNames.FAMILY_NAME)
    @SerializedName(StandardClaimNames.FAMILY_NAME)
    @Column(name = StandardClaimNames.FAMILY_NAME)
    private String familyName;

    @JsonProperty(StandardClaimNames.GIVEN_NAME)
    @SerializedName(StandardClaimNames.GIVEN_NAME)
    @Column(name = StandardClaimNames.GIVEN_NAME)
    private String givenName;

    @JsonProperty(StandardClaimNames.NAME)
    @SerializedName(StandardClaimNames.NAME)
    private String name;

    @Id
    @JsonProperty(IdpParameterNames.USERNAME)
    @SerializedName(IdpParameterNames.USERNAME)
    private String username;

    @JsonProperty(StandardClaimNames.PREFERRED_USERNAME)
    @SerializedName(StandardClaimNames.PREFERRED_USERNAME)
    @Column(name = StandardClaimNames.PREFERRED_USERNAME)
    private String preferredUsername;

    @GsonIgnore
    @JsonIgnore
    private String password;

    @JsonProperty(StandardClaimNames.PHONE_NUMBER)
    @SerializedName(StandardClaimNames.PHONE_NUMBER)
    @Column(name = StandardClaimNames.PHONE_NUMBER)
    private String phoneNumber;

    @JsonProperty(StandardClaimNames.PHONE_NUMBER_VERIFIED)
    @SerializedName(StandardClaimNames.PHONE_NUMBER_VERIFIED)
    @Column(name = StandardClaimNames.PHONE_NUMBER_VERIFIED)
    private boolean validPhoneNumber;

    @JsonProperty(StandardClaimNames.EMAIL)
    @SerializedName(StandardClaimNames.EMAIL)
    private String email;

    @JsonProperty(StandardClaimNames.EMAIL_VERIFIED)
    @SerializedName(StandardClaimNames.EMAIL_VERIFIED)
    @Column(name = StandardClaimNames.EMAIL_VERIFIED)
    @Setter
    private boolean validEmail;

    @JsonProperty(StandardClaimNames.BIRTHDATE)
    @SerializedName(StandardClaimNames.BIRTHDATE)
    private String birthdate;

    @JsonProperty(StandardClaimNames.GENDER)
    @SerializedName(StandardClaimNames.GENDER)
    private String gender;

    @JsonProperty(StandardClaimNames.ADDRESS)
    @SerializedName(StandardClaimNames.ADDRESS)
    private String address;

    @JsonProperty(StandardClaimNames.UPDATED_AT)
    @SerializedName(StandardClaimNames.UPDATED_AT)
    @Column(name = StandardClaimNames.UPDATED_AT)
    private Instant updatedAt;

    // 하위 엔티티, LinkedHashSet 초기화하여 NPE 방지
    @OneToMany(mappedBy = "users", orphanRemoval = true, cascade = CascadeType.ALL)
    @Getter(value = AccessLevel.NONE)
    @GsonIgnore
    @JsonIgnore
    private Set<UserAuthority> userAuthorityList = new LinkedHashSet<>();

    @Getter(value = AccessLevel.NONE)
    @JsonProperty(IdpParameterNames.ACCOUNT_NON_EXPIRED)
    @SerializedName(IdpParameterNames.ACCOUNT_NON_EXPIRED)
    @Column(name = IdpParameterNames.ACCOUNT_NON_EXPIRED)
    private boolean accountNonExpired;

    @Getter(value = AccessLevel.NONE)
    @JsonProperty(IdpParameterNames.ACCOUNT_NON_LOCKED)
    @SerializedName(IdpParameterNames.ACCOUNT_NON_LOCKED)
    @Column(name = IdpParameterNames.ACCOUNT_NON_LOCKED)
    @Setter
    private boolean accountNonLocked;

    @Getter(value = AccessLevel.NONE)
    @JsonProperty(IdpParameterNames.CREDENTIALS_NON_EXPIRED)
    @SerializedName(IdpParameterNames.CREDENTIALS_NON_EXPIRED)
    @Column(name = IdpParameterNames.CREDENTIALS_NON_EXPIRED)
    private boolean credentialsNonExpired;

    @Getter(value = AccessLevel.NONE)
    @Setter
    @JsonProperty(IdpParameterNames.ENABLED)
    @SerializedName(IdpParameterNames.ENABLED)
    private boolean enabled;

    @JsonProperty(IdpParameterNames.ACCOUNT_REMAINING_COUNT)
    @SerializedName(IdpParameterNames.ACCOUNT_REMAINING_COUNT)
    @Column(name = IdpParameterNames.ACCOUNT_REMAINING_COUNT)
    @Setter
    private int accountRemainingCount = 5;

    private IdpUser(IdpUserBuilder builder) {
        this.familyName = builder.familyName;
        this.givenName = builder.givenName;
        this.name = builder.name;
        this.username = builder.username;
        this.preferredUsername = builder.preferredUsername;
        this.password = builder.password;
        this.phoneNumber = builder.phoneNumber;
        this.validPhoneNumber = builder.validPhoneNumber;
        this.email = builder.email;
        this.validEmail = builder.validEmail;
        this.birthdate = builder.birthdate;
        this.gender = builder.gender;
        this.address = builder.address;
        this.updatedAt = builder.updatedAt;
        this.userAuthorityList = builder.userAuthorityList;
        this.accountNonExpired = builder.accountNonExpired;
        this.accountNonLocked = builder.accountNonLocked;
        this.credentialsNonExpired = builder.credentialsNonExpired;
        this.enabled = builder.enabled;
        this.accountRemainingCount = builder.accountRemainingCount;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        userAuthorityList.forEach((userAuthority) -> {
            authorities.add(new SimpleGrantedAuthority(userAuthority.getUserAuthorityId().getAuthority()));
        });

        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public String getName() {
        return this.name;
    }

    public static IdpUserBuilder builder() {
        return new IdpUserBuilder();
    }

    public static IdpUserBuilder withUserInfo(UserSignInfo userInfo, PasswordEncoder passwordEncoder) {
        return new IdpUserBuilder().username(userInfo.getUsername())
                .familyName(userInfo.getFamilyName())
                .givenName(userInfo.getGivenName())
                .password(userInfo.getPassword())
                .phoneNumber(userInfo.getPhoneNumber())
                .validPhoneNumber(userInfo.isValidPhoneNumber())
                .email(userInfo.getEmail())
                .validEmail(userInfo.isValidEmail())
                .birthdate(userInfo.getBirthdate())
                .gender(userInfo.getGender())
                .address(userInfo.getAddress())
                .passwordEncoder(password -> passwordEncoder.encode(password));
    }

    @Override
    public String toString() {
        return "{" +
            " familyName='" + getFamilyName() + "'" +
            ", givenName='" + getGivenName() + "'" +
            ", name='" + getName() + "'" +
            ", username='" + getUsername() + "'" +
            ", preferredUsername='" + getPreferredUsername() + "'" +
            ", password='" + getPassword() + "'" +
            ", phoneNumber='" + getPhoneNumber() + "'" +
            ", validPhoneNumber='" + isValidPhoneNumber() + "'" +
            ", email='" + getEmail() + "'" +
            ", validEmail='" + isValidEmail() + "'" +
            ", birthdate='" + getBirthdate() + "'" +
            ", gender='" + getGender() + "'" +
            ", address='" + getAddress() + "'" +
            ", updatedAt='" + getUpdatedAt() + "'" +
            ", userAuthorityList='" + getAuthorities() + "'" +
            ", accountNonExpired='" + isAccountNonExpired() + "'" +
            ", accountNonLocked='" + isAccountNonLocked() + "'" +
            ", credentialsNonExpired='" + isCredentialsNonExpired() + "'" +
            ", enabled='" + isEnabled() + "'" +
            ", accountRemainingCount='" + getAccountRemainingCount() + "'" +
            "}";
    }

    public static class IdpUserBuilder {
        private IdpUserBuilder() {
        }

        private String familyName;
        private String givenName;
        private String name;
        private String username;
        private String preferredUsername;
        private String password;
        private String phoneNumber;
        private boolean validPhoneNumber;
        private String email;
        private boolean validEmail;
        private String birthdate;
        private String gender;
        private String address;
        private Instant updatedAt = Instant.now();
        private List<GrantedAuthority> authorities = new ArrayList<>(
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        private boolean accountNonExpired = true;
        private boolean accountNonLocked = true;
        private boolean credentialsNonExpired = true;
        private boolean enabled = true;
        private int accountRemainingCount = 5;
        private Function<String, String> passwordEncoder = password -> password;
        private Set<UserAuthority> userAuthorityList = new LinkedHashSet<>();

        public IdpUser build() {
            this.name = familyName.concat(givenName);
            this.preferredUsername = this.username;

            String encodedPassword = this.passwordEncoder.apply(this.password);
            this.password = encodedPassword;

            for (GrantedAuthority authority : authorities) {
                UserAuthorityId authorityId = new UserAuthorityId();
                authorityId.setUsername(this.username);
                authorityId.setAuthority(authority.getAuthority());

                UserAuthority userAuthority = new UserAuthority();
                userAuthority.setUserAuthorityId(authorityId);
                this.userAuthorityList.add(userAuthority);
            }
            
            IdpUser user = new IdpUser(this);
            user.userAuthorityList.forEach((userAuthority) -> {
                userAuthority.setUsers(user);
            });

            return user;
        }

        public IdpUserBuilder familyName(String familyName) {
            this.familyName = familyName;
            return this;
        }

        public IdpUserBuilder givenName(String givenName) {
            this.givenName = givenName;
            return this;
        }

        public IdpUserBuilder username(String username) {
            this.username = username;
            return this;
        }

        public IdpUserBuilder password(String password) {
            this.password = password;
            return this;
        }

        public IdpUserBuilder phoneNumber(String phoneNumber) {
            this.phoneNumber = phoneNumber;
            return this;
        }

        public IdpUserBuilder validPhoneNumber(boolean validPhoneNumber) {
            this.validPhoneNumber = validPhoneNumber;
            return this;
        }

        public IdpUserBuilder email(String email) {
            this.email = email;
            return this;
        }

        public IdpUserBuilder validEmail(boolean validEmail) {
            this.validEmail = validEmail;
            return this;
        }

        public IdpUserBuilder birthdate(String birthdate) {
            this.birthdate = birthdate;
            return this;
        }

        public IdpUserBuilder gender(String gender) {
            this.gender = gender;
            return this;
        }

        public IdpUserBuilder address(String address) {
            this.address = address;
            return this;
        }

        public IdpUserBuilder updatedAt(Instant updatedAt) {
            this.updatedAt = updatedAt;
            return this;
        }

        public IdpUserBuilder authorities(GrantedAuthority... authorities) {
            return authorities(Arrays.asList(authorities));
        }

        public IdpUserBuilder authorities(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<>(roles.length);
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            return authorities(authorities);
        }

        public IdpUserBuilder authorities(List<GrantedAuthority> authorities) {
            authorities.forEach(v -> {
                if (!this.authorities.contains(v))
                    this.authorities.add(v);
            });
            return this;
        }

        public IdpUserBuilder accountNonExpired(boolean accountNonExpired) {
            this.accountNonExpired = accountNonExpired;
            return this;
        }

        public IdpUserBuilder accountNonLocked(boolean accountNonLocked) {
            this.accountNonLocked = accountNonLocked;
            return this;
        }

        public IdpUserBuilder credentialsNonExpired(boolean credentialsNonExpired) {
            this.credentialsNonExpired = credentialsNonExpired;
            return this;
        }

        public IdpUserBuilder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public IdpUserBuilder accountRemainingCount(int count) {
            this.accountRemainingCount = count;
            return this;
        }

        public IdpUserBuilder passwordEncoder(Function<String, String> encoder) {
            if (Objects.isNull(encoder)){
                IdpError error = CommonUtils.generateError(IdpStatus.NULL_ENCODER);
                throw new IdpApiException(error);
            }
                
            this.passwordEncoder = encoder;
            return this;
        }
    }
}
