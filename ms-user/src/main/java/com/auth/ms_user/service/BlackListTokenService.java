package com.auth.ms_user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth.ms_user.repository.BlacklistedTokenRepository;

@Service
public class BlackListTokenService {
    
    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;
}
