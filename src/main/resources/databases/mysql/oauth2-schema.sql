SET sql_mode = '';

CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    attributes blob DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value blob DEFAULT NULL,
    authorization_code_issued_at timestamp NULL,
    authorization_code_expires_at timestamp NULL,
    authorization_code_metadata blob DEFAULT NULL,
    access_token_value blob DEFAULT NULL,
    access_token_issued_at timestamp NULL,
    access_token_expires_at timestamp NULL,
    access_token_metadata blob DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value blob DEFAULT NULL,
    oidc_id_token_issued_at timestamp NULL,
    oidc_id_token_expires_at timestamp NULL,
    oidc_id_token_metadata blob DEFAULT NULL,
    refresh_token_value blob DEFAULT NULL,
    refresh_token_issued_at timestamp NULL,
    refresh_token_expires_at timestamp NULL,
    refresh_token_metadata blob DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorized_client (
  client_registration_id varchar(100) NOT NULL,
  principal_name varchar(200) NOT NULL,
  access_token_type varchar(100) NOT NULL,
  access_token_value blob NOT NULL,
  access_token_issued_at timestamp NOT NULL,
  access_token_expires_at timestamp NOT NULL,
  access_token_scopes varchar(1000) DEFAULT NULL,
  refresh_token_value blob DEFAULT NULL,
  refresh_token_issued_at timestamp NULL,
  created_at timestamp NOT NULL,
  PRIMARY KEY (client_registration_id, principal_name)
);

CREATE TABLE IF NOT EXISTS users(
    family_name VARCHAR(50) NOT NULL,
    given_name VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    username VARCHAR(50) NOT NULL,
    preferred_username VARCHAR(50) NOT NULL,
    password VARCHAR(200) NOT NULL,
    phone_number VARCHAR(200) NOT NULL,
    phone_number_verified BOOLEAN NOT NULL,
    email VARCHAR(200) NOT NULL,
    email_verified BOOLEAN NOT NULL,
    birthdate VARCHAR(200) NOT NULL,
    gender VARCHAR(50) NOT NULL,
    address VARCHAR(1000) NOT NULL,
    updated_at timestamp NULL,
    account_non_expired BOOLEAN NOT NULL,
    account_non_Locked BOOLEAN NOT NULL,
    credentials_non_expired BOOLEAN NOT NULL,
    account_remaining_count INT UNSIGNED NOT NULL,
    enabled BOOLEAN NOT NULL,
    PRIMARY KEY(username)
);

CREATE TABLE IF NOT EXISTS authorities (
  users_username varchar(50) NOT NULL,
  authority varchar(50) NOT NULL,
  UNIQUE KEY ix_auth_username (users_username,authority),
  CONSTRAINT fk_authorities_users FOREIGN KEY (users_username) REFERENCES users (username)
);

CREATE TABLE IF NOT EXISTS persistent_logins (
  username varchar(50) NOT NULL,
  series varchar(100) NOT NULL,
  token varchar(200) NOT NULL,
  last_used timestamp NOT NULL,
  PRIMARY KEY(series),
  CONSTRAINT fk_persistent_logins FOREIGN KEY (username) REFERENCES users (username)
);

CREATE TABLE IF NOT EXISTS persistent_logins (
  username varchar(50) NOT NULL,
  series varchar(100) NOT NULL,
  token varchar(200) NOT NULL,
  last_used timestamp NOT NULL,
  PRIMARY KEY(series),
  CONSTRAINT fk_persistent_logins FOREIGN KEY (username) REFERENCES users (username)
);

CREATE TABLE IF NOT EXISTS email_token (
  id varchar(40) NOT NULL,
  username varchar(50) NOT NULL,
  expiration_date timestamp NOT NULL,
  expired tinyint(1) NOT NULL,
  PRIMARY KEY(id)
);