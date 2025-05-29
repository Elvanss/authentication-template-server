package com.auth.ms_user.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth.ms_user.domain.BlacklistToken;

@Repository
public interface  BlacklistedTokenRepository extends JpaRepository<BlacklistToken, UUID>{

}
