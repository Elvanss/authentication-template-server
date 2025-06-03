    package com.auth.ms_user.controller;

import java.util.UUID;

import javax.security.auth.login.AccountLockedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Description;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth.ms_user.domain.User;
import com.auth.ms_user.service.AuthService;
import com.auth.ms_user.service.JwtService;
import com.template.shared.api.ApiResponse;
import com.template.shared.api.user.req.ChangePasswordRequest;
import com.template.shared.api.user.req.LoginDtoRequest;
import com.template.shared.api.user.req.VerifyOtpRequest;
import com.template.shared.api.user.res.ChangePasswordResponse;
import com.template.shared.api.user.res.LoginResponse;
import com.template.shared.api.user.res.UserResponse;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController (AuthService authService, JwtService jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }

    @RequestMapping(value = "/v1/register", method = RequestMethod.POST)
    @Description("Register a new user with given details.")
    public ResponseEntity<ApiResponse<UserResponse>> registerUser
    (
        @RequestBody @Validated User user
    ) 
    {
        logger.info("Registering user with email: {}", user.getEmail());
        ApiResponse<UserResponse> response = authService.registerUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @RequestMapping(value = "/v1/login", method = RequestMethod.POST)
    @Description("Send the user email and password.")
    public ResponseEntity<ApiResponse<Void>> login
    (
        @RequestBody @Validated LoginDtoRequest loginDtoReq
    ) 
    throws AccountLockedException 
    {
        logger.info("Processing login request for email: {}", loginDtoReq.getEmail());
        ApiResponse<Void> response = authService.userLogin(loginDtoReq);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(value = "/v1/resend-otp", method = RequestMethod.POST)
    @Description("Resend the OTP to the user after checking user credentials successfully.")
    public ResponseEntity<ApiResponse<Void>> resendOtp(
        @RequestBody @Validated String email
    ) {
        logger.info("Resending OTP for email: {}",email);
        ApiResponse<Void> response = authService.resendOtp(email);
        return ResponseEntity.ok(response);
    }

    @RequestMapping(value = "/v1/verify-otp", method = RequestMethod.POST)
    @Description("Verify the OTP code sent to the user.")
    public ResponseEntity<ApiResponse<LoginResponse>> verifyOtp
    (
        @RequestBody @Validated VerifyOtpRequest otpRequest
    )
    {
        logger.info("Processing OTP verification for email: {}", otpRequest.getEmail());
        ApiResponse<LoginResponse> response = authService.verifyOtp(otpRequest);
        return ResponseEntity.ok(response);
    }

    // @RequestMapping(value = "/v1/refresh-token", method = RequestMethod.POST)
    // @Description("Generate a new access token using the refresh token.")


    @RequestMapping(value = "/v1/change-password", method = RequestMethod.PATCH)
    @Description("Change the password for the user.")
    public ResponseEntity<ApiResponse<ChangePasswordResponse>> changePassword
    (   
        @RequestHeader("Authorization") String token,
        @RequestBody @Validated ChangePasswordRequest changePasswordRequest
    )
    {
        UUID userID = this.jwtService.extractUserIdFromToken(token);
        logger.info("Processing password change request for email: {}", userID);
        ApiResponse<ChangePasswordResponse> response = authService.changePassword(userID, changePasswordRequest);
        return ResponseEntity.ok(response);
    }

    // @RequestMapping(value = "/v1/forgot-password", method = RequestMethod.POST)
    // @Description("Send a password reset link to the user's email.")
    // public ResponseEntity<ApiResponse<String>> forgotPassword
    // (
    //     @RequestBody @Validated String email
    // ) 
    // {
    //     logger.info("Processing forgot password request for email: {}", email);
    //     ApiResponse<String> response = authService.forgotPassword(email);
    //     return ResponseEntity.ok(response);
    // }

    // @RequestMapping(value = "/v1/reset-password", method = RequestMethod.POST)
    // @Description("Reset the user's password with the provided reset token.")
    // public ResponseEntity<ApiResponse<ResetPasswordResponse>> resetPassword
    // (
    //     @RequestBody @Validated ResetPasswordRequest resetPasswordRequest
    // ) 
    // {
    //     ApiResponse<String> response = authService.resetPassword(resetPasswordRequest);
    //     return ResponseEntity.ok(response);
    // }

    // @RequestMapping(value = "/v1/logout", method = RequestMethod.POST)
    // @Description("Logout the user by invalidating the session or token.")



}
