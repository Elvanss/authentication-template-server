package com.auth.ms_notification.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth.ms_notification.application.IOtpService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/otp")
@RequiredArgsConstructor
public class OtpController {

    private final IOtpService otpService;

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifyOtp
    (
        @RequestParam(name = "email") String email, 
        @RequestParam(name = "otp") Integer otp
    ) 
    {
        boolean valid = otpService.verifyOtp(email, otp);
        return ResponseEntity.ok(valid);
    }

    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteOtp(@RequestParam String email) throws Exception {
        otpService.deleteOtp(email);
        return ResponseEntity.ok("OTP deleted");
    }
}
