package com.auth.ms_user.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Description;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth.ms_user.domain.User;
import com.auth.ms_user.service.AuthService;
import com.template.shared.api.ApiResponse;
import com.template.shared.api.user.event.OtpRequestEvent;
import com.template.shared.api.user.req.LoginDtoRequest;
import com.template.shared.api.user.req.VerifyOtpRequest;
import com.template.shared.api.user.res.LoginResponse;
import com.template.shared.api.user.res.UserResponse;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController (AuthService authService) {
        this.authService = authService;
    }

    @RequestMapping(value = "/v1/register", method = RequestMethod.POST)
    @Description("Register a new user with given details.")
    public ResponseEntity<ApiResponse<UserResponse>> registerUser(@RequestBody @Validated User user) {
        logger.info("Registering user with email: {}", user.getEmail());
        ApiResponse<UserResponse> response = authService.registerUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @RequestMapping(value = "/v1/login", method = RequestMethod.POST)
    @Description("Send the user email and password.")
    public ResponseEntity<ApiResponse<OtpRequestEvent>> login(@RequestBody @Validated LoginDtoRequest loginDtoReq) {
        logger.info("Processing login request for email: {}", loginDtoReq.getEmail());
        ApiResponse<OtpRequestEvent> response = authService.userLogin(loginDtoReq);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(value = "/v1/verify-otp", method = RequestMethod.POST)
    @Description("Verify the OTP code sent to the user.")
    public ResponseEntity<ApiResponse<LoginResponse>> verifyOtp(@RequestBody @Validated VerifyOtpRequest otpRequest) {
        logger.info("Processing OTP verification for email: {}", otpRequest.getEmail());
        ApiResponse<LoginResponse> response = authService.verifyOtp(otpRequest);
        return ResponseEntity.ok(response);
    }
}
