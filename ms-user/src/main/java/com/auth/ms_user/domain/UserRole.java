package com.auth.ms_user.domain;

import java.util.UUID;

import com.auth.ms_user.utils.constants.Role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "\"user_roles\"")
public class UserRole {

    @Id
    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "role")
    @Enumerated(
        value = jakarta.persistence.EnumType.STRING
    )
    private Role role;
}
