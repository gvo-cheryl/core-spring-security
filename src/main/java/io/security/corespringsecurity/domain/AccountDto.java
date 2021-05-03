package io.security.corespringsecurity.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
public class AccountDto {

    private Long Id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}