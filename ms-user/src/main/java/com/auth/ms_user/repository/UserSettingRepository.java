package com.auth.ms_user.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth.ms_user.domain.UserSetting;

@Repository
public interface UserSettingRepository extends JpaRepository<UserSetting, UUID> {
    
}
