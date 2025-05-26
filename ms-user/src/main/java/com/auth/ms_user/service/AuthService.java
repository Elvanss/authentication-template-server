package com.auth.ms_user.service;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Description;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;

import com.auth.ms_user.client.OtpServiceClient;
import com.auth.ms_user.config.KafkaTopicsConfig;
import com.auth.ms_user.domain.User;
import com.auth.ms_user.domain.UserRole;
import com.auth.ms_user.domain.UserSetting;
import com.auth.ms_user.event.OtpRequestEvent;
import com.auth.ms_user.exception.InvalidInputException;
import com.auth.ms_user.mapper.UserMapper;
import com.auth.ms_user.producer.OtpKafkaProducer;
import com.auth.ms_user.repository.UserRepository;
import com.auth.ms_user.repository.UserRoleRepository;
import com.auth.ms_user.repository.UserSettingRepository;
import com.auth.ms_user.security.UserDetailsImpl;
import com.auth.ms_user.security.UserDetailsServiceImpl;
import com.auth.ms_user.utils.constants.Role;
import com.auth.ms_user.utils.constants.Status;
import com.template.shared.api.ApiResponse;
import com.template.shared.api.user.req.LoginDtoRequest;
import com.template.shared.api.user.req.VerifyOtpRequest;
import com.template.shared.api.user.res.LoginResponse;
import com.template.shared.api.user.res.UserResponse;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class AuthService {

    private final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserSettingRepository userSettingRepository;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final OtpKafkaProducer otpKafkaProducer;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final KafkaTopicsConfig kafkaTopicsConfig;
    private final OtpServiceClient otpServiceClient;

    // @Transactional
    // public ApiResponse<OtpRequestEvent> userLogin(LoginDtoRequest loginDtoReq) {
    //     User authenticatedUser = authenticate(loginDtoReq);
    
    //     if (authenticatedUser == null) {
    //         return new ApiResponse<>(false, "No Account found!", null);
    //     }
    
    //      if (authenticatedUser.isLocked()) {
    //         logger.warn("Account is locked for user with email: {}", authenticatedUser.getEmail());
        
    //         OtpRequestEvent accountLockedEvent = buildOtpRequestEvent(authenticatedUser);
        
    //         try {
    //             otpKafkaProducer.sendMessage(accountLockedEvent, kafkaTopicsConfig.getProducedTopic("user.account.locked").getName());
    //             logger.info("Account locked event sent to Kafka for user: {}", authenticatedUser.getEmail());
    //         } catch (Exception e) {
    //             logger.error("Failed to send account locked event to Kafka for user: {}", authenticatedUser.getEmail(), e);
    //             return new ApiResponse<>(false, "Failed to process account-locked event", null);
    //         }
        
    //         return new ApiResponse<>(false, "This account is locked!", accountLockedEvent);
    //     }
    
    //     if (!passwordEncoder.matches(loginDtoReq.getPassword(), authenticatedUser.getPassword())) {
    //         if (handleFailedAttempts(authenticatedUser)) {
    //             return new ApiResponse<>(false, "Account is locked", null);
    //         }
    //         return new ApiResponse<>(false, "You entered the wrong password or email!", null);
    //     }
    
    //     logger.info("Quick check user with account id: {} and user name {}", 
    //             authenticatedUser.getUserId(), 
    //             authenticatedUser.getEmail()
    //     );
    
    //     OtpRequestEvent otpRequestEvent = buildOtpRequestEvent(authenticatedUser);
    //     otpKafkaProducer.sendMessage(otpRequestEvent, kafkaTopicsConfig.getProducedTopic("user.otp.requested").getName());
    
    //     return new ApiResponse<>(true, "User credentials returned!", otpRequestEvent);
    // }

    @Transactional
    public ApiResponse<OtpRequestEvent> userLogin(LoginDtoRequest loginDtoReq) {
        User authenticatedUser = authenticate(loginDtoReq);
    
        if (authenticatedUser == null) {
            return new ApiResponse<>(false, "No Account found!", null);
        }
    
         if (authenticatedUser.isLocked()) {
            logger.warn("Account is locked for user with email: {}", authenticatedUser.getEmail());
        
            OtpRequestEvent accountLockedEvent = buildOtpRequestEvent(authenticatedUser);
        
            try {
                otpKafkaProducer.sendMessage(accountLockedEvent, kafkaTopicsConfig.getProducedTopic("user.account.locked").getName());
                logger.info("Account locked event sent to Kafka for user: {}", authenticatedUser.getEmail());
            } catch (Exception e) {
                logger.error("Failed to send account locked event to Kafka for user: {}", authenticatedUser.getEmail(), e);
                return new ApiResponse<>(false, "Failed to process account-locked event", null);
            }
        
            return new ApiResponse<>(false, "This account is locked!", accountLockedEvent);
        }
    
        if (!passwordEncoder.matches(loginDtoReq.getPassword(), authenticatedUser.getPassword())) {
            if (handleFailedAttempts(authenticatedUser)) {
                return new ApiResponse<>(false, "Account is locked", null);
            }
            return new ApiResponse<>(false, "You entered the wrong password or email!", null);
        }
    
        logger.info("Quick check user with account id: {} and user name {}", 
                authenticatedUser.getUserId(), 
                authenticatedUser.getEmail()
        );
    
        OtpRequestEvent otpRequestEvent = buildOtpRequestEvent(authenticatedUser);
        otpKafkaProducer.sendMessage(otpRequestEvent, kafkaTopicsConfig.getProducedTopic("user.otp.requested").getName());
    
        return new ApiResponse<>(true, "User credentials returned!", otpRequestEvent);
    }

    @Transactional
    public ApiResponse<LoginResponse> verifyOtp(VerifyOtpRequest otpRequest) {
        try {
            // Log the request
            logger.info("Verifying OTP for email: {} with OTP: {}", otpRequest.getEmail(), otpRequest.getOtp());
    
            // Call the OTP verification service using Feign client
            boolean otpVerificationResponse = otpServiceClient.verifyOtp(otpRequest.getEmail(), otpRequest.getOtp());
            logger.info("Response from OTP verification service: {}", otpVerificationResponse);
    
            // Validate the response (if needed)
            if (!otpVerificationResponse) {
                logger.warn("Invalid OTP for user with email: {}", otpRequest.getEmail());
                return new ApiResponse<>(false, "Invalid OTP", null);
            }
    
            // Load user details
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsServiceImpl.loadUserByUsername(otpRequest.getEmail());
    
            // Generate JWT token for the user
            String token = jwtService.generateToken(userDetails);
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setToken(token);
            logger.info("Generated login response: {}", loginResponse);
    
            // Delete the OTP after successful verification
            otpServiceClient.deleteOtp(otpRequest.getEmail());
            logger.info("Deleted OTP for user with email: {}", otpRequest.getEmail());
    
            // Return success response
            return new ApiResponse<>(true, "OTP verified successfully", loginResponse);
    
        } catch (InvalidInputException e) {
            logger.error("User not found with email: {}", otpRequest.getEmail(), e);
            return new ApiResponse<>(false, e.getMessage(), null);
        } catch (UsernameNotFoundException | RestClientException e) {
            logger.error("An error occurred during OTP verification for user with email: {}", otpRequest.getEmail(), e);
            return new ApiResponse<>(false, "An unexpected error occurred", null);
        }
    }
    @Transactional
    @Description("Register a new user with given details.")
    public ApiResponse<UserResponse> registerUser(User user) {
        try {
            if (userRepository.findByEmail(user.getEmail()).isPresent()) {
                throw new InvalidInputException("The email address is already in use.");
            }
            user.setPassword(this.passwordEncoder.encode(user.getPassword()));
            this.userRepository.save(user);

            UserRole role = new UserRole();
            role.setUserId(user.getUserId());
            role.setRole(Role.USER);
            this.userRoleRepository.save(role);

            UserSetting userSetting = new UserSetting();
            userSetting.setUserId(user.getUserId());
            userSetting.setLanguage("VN");
            userSetting.setStatus(Status.PENDING_VERIFICATION);
            this.userSettingRepository.save(userSetting);
            return new ApiResponse<>(true, "User registered successfully", this.userMapper.toUserDto(user));
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * External functions for main service methods
     * Start from here [^.^]
     */
    public User authenticate (LoginDtoRequest loginDtoReq) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDtoReq.getEmail(),
                loginDtoReq.getPassword()
        ));
        return 
                this.userRepository.findByEmail
                    (
                        loginDtoReq.getEmail()
                    )
                .orElseThrow
                    (
                        () -> new InvalidInputException("User not found")
                    );
                
    }

    private OtpRequestEvent buildOtpRequestEvent(User user) {
        return OtpRequestEvent.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .timestamp(Instant.now())
                .build();
    }

    private boolean handleFailedAttempts(User user) {
        Integer failedAttempted = user.getAttemptedCount() + 1;
        user.setAttemptedCount(failedAttempted);
    
        if (failedAttempted >= 5) {
            user.setLocked(true);
            userRepository.save(user);
    
            // Build and send account locked event
            OtpRequestEvent accountLockedEvent = buildOtpRequestEvent(user);
            otpKafkaProducer.sendMessage(accountLockedEvent, "account-locked-events");
    
            return true; // Account is locked
        }
    
        userRepository.save(user); // Save the updated attempt count
        return false; // Account is not locked
    }
}
