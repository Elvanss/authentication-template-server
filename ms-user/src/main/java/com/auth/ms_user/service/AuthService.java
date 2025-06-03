package com.auth.ms_user.service;

import java.time.Duration;
import java.util.UUID;

import javax.security.auth.login.AccountLockedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Description;
import org.springframework.data.redis.core.RedisTemplate;
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
import com.template.shared.api.user.event.EmailRequestEvent;
import com.template.shared.api.user.req.ChangePasswordRequest;
import com.template.shared.api.user.req.LoginDtoRequest;
import com.template.shared.api.user.req.ResetPasswordRequest;
import com.template.shared.api.user.req.VerifyOtpRequest;
import com.template.shared.api.user.res.ChangePasswordResponse;
import com.template.shared.api.user.res.LoginResponse;
import com.template.shared.api.user.res.ResetPasswordResponse;
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
    private final RedisTemplate<String, String> redisTemplate;
    private final NotificationService notificationService;




    @Transactional
    @Description("Authenticate the user and initiate an OTP verification event. " +
        "Returns an OTP request event if successful or if the account is locked.")
    public ApiResponse<Void> userLogin(LoginDtoRequest loginDtoReq) throws AccountLockedException {
        User authenticatedUser = authenticate(loginDtoReq);
    
        if (authenticatedUser == null) {
            return new ApiResponse<>(false, "No Account found!", null);
        }
    
        if (authenticatedUser.isLocked()) {
            logger.warn("Account is locked for user with email: {}", authenticatedUser.getEmail());
    
            try {
                notificationService.sendAccountLockedEventAsync(authenticatedUser);
                logger.info("Account locked event sent to Kafka for user: {}", authenticatedUser.getEmail());
            } catch (Exception e) {
                logger.error("Failed to send account locked event to Kafka for user: {}", authenticatedUser.getEmail(), e);
                return new ApiResponse<>(false, "Failed to process account-locked event", null);
            }
    
            throw new AccountLockedException("This account is locked!");
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
    
        // Store login state in 5 minutes
        redisTemplate.opsForValue().set(
            "loginState:" + authenticatedUser.getEmail(),
            "true",
            Duration.ofMinutes(5)
        );
        logger.info("Login state set in Redis for email: {}", authenticatedUser.getEmail());
    
        notificationService.sendOtpRequestEventAsync(authenticatedUser);
    
        return new ApiResponse<>(true, "User credentials returned!", null);
    }

    @Transactional
    @Description("Resend the OTP to the user after checking user credentials successfully.")
    public ApiResponse<Void> resendOtp(String email) {
        try {
            // Step 1: Check if the user has a valid login state
            logger.info("Value of checkLoginValid for email "+ checkLoginValid(email));
            if (!checkLoginValid(email)) {
                throw new IllegalArgumentException("User credentials not validated. Please log in first.");
            }
    
            // Step 2: Validate user existence
            User authenticatedUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
    
            // Step 3: Send the OTP request event to ms-notification via Kafka
            notificationService.sendOtpRequestEventAsync(authenticatedUser);
            logger.info("Sent OTP request event to ms-notification for user: {}", authenticatedUser.getEmail());
    
            // Step 4: Return success response
            return new ApiResponse<>(true, "OTP request sent to notification service", null);
        } catch (IllegalArgumentException e) {
            logger.error("Error resending OTP: {}", e.getMessage());
            return new ApiResponse<>(false, e.getMessage(), null);
        } catch (Exception e) {
            logger.error("Unexpected error while resending OTP for email: {}", email, e);
            return new ApiResponse<>(false, "An unexpected error occurred while resending OTP", null);
        }
    }

    @Transactional
    @Description("Verify the user's OTP using the OTP Service. " +
        "Generates a JWT token upon successful verification.")
    public ApiResponse<LoginResponse> verifyOtp(VerifyOtpRequest otpRequest) {

        // Check if the user has a valid login state in Redis
        logger.info("Value of checkLoginValid for email "+ checkLoginValid(otpRequest.getEmail()));
        if (!checkLoginValid(otpRequest.getEmail())) {
            throw new IllegalArgumentException("User credentials not validated. Please log in first.");
        }

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
    @Description("Change the user's password after verifying the old password and the password strength. " +
        "Handles incrementing failed attempts if passwords do not match.")
    public ApiResponse<ChangePasswordResponse> changePassword(UUID userId, ChangePasswordRequest changePasswordRequest) {
        try {
            // Step 1: Validate user existence
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));
    
            // Step 2: Verify old password
            if (!passwordEncoder.matches(changePasswordRequest.getOldPassword(), user.getPassword())) {
                user.incrementAttemptedCount();
                userRepository.save(user);
                return new ApiResponse<>(
                        false,
                        "Old password is incorrect",
                        new ChangePasswordResponse(false, user.getAttemptedCount())
                );
            }
    
            // Step 3: Validate new password and confirm password match
            if (!changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmPassword())) {
                user.incrementAttemptedCount();
                userRepository.save(user); // Save attempted count
                return new ApiResponse<>(
                        false,
                        "New password and confirm password do not match",
                        new ChangePasswordResponse(false, user.getAttemptedCount())
                );
            }
    
            // Step 4: Check password strength
            if (!isPasswordStrong(changePasswordRequest.getNewPassword())) {
                return new ApiResponse<>(
                        false,
                        "Password does not meet strength requirements",
                        new ChangePasswordResponse(false, user.getAttemptedCount())
                );
            }
    
            // Step 5: Update password
            user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
            user.resetAttemptedCount(); // Reset attempted count on success
            userRepository.save(user);
    
            // Step 6: Send Kafka event (outside transaction)
            notificationService.sendAccountLockedEventAsync(user);
    
            return new ApiResponse<>(
                    true,
                    "Password changed successfully",
                    new ChangePasswordResponse(true, user.getAttemptedCount())
            );
        } catch (IllegalArgumentException e) {
            return new ApiResponse<>(false, e.getMessage(), null);
        } catch (Exception e) {
            logger.error("Error changing password for user with ID: {}", userId, e);
            return new ApiResponse<>(false, "An error occurred while changing the password", null);
        }
    }
    
    private boolean isPasswordStrong(String password) {
        return password.length() >= 8 && password.matches(".*[!@#$%^&*()].*");
    }

    @Transactional
    @Description("Register a new user with default role and settings. " +
        "Encodes the user's password and persists the record.")
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

    @Transactional
    public ApiResponse<String> forgotPassword(String email) {    
        // Check if user exists
        User authenticatedUser = this.userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));

        // Tell ms-notification to send a reset link
        notificationService.sendResetPasswordEmailAsync(authenticatedUser);
        logger.info("Password reset link sent to email: {}", email);
        
        return new ApiResponse<>(true, "Password reset link sent successfully", null);
    }

    @Transactional
    public ApiResponse<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest) {

        // Step 1: Validate reset token
        String resetToken = resetPasswordRequest.getResetToken();
        if (resetToken == null || resetToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Reset token cannot be null or empty");
        }
    
        // Step 2: Retrieve email from Redis
        String email = redisTemplate.opsForValue().get("resetToken:" + resetToken);
        if (email == null) {
            throw new IllegalArgumentException("The reset token is invalid or has expired. Please request a new password reset.");
        }
    
        // Step 3: Validate new password
        String newPassword = resetPasswordRequest.getNewPassword();
        String confirmPassword = resetPasswordRequest.getConfirmPassword();
        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("New password cannot be null or empty");
        }
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }
        if (!newPassword.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$")) {
            throw new IllegalArgumentException("Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character");
        }
    
        // Step 4: Update user's password
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    
        // Step 5: Invalidate the reset token
        redisTemplate.delete("resetToken:" + resetToken);
    
        // Step 6: Notify the user
        notificationService.sendResetPasswordEmailAsync(user);
    
        logger.info("Password reset successfully for email: {}", email);
        return new ApiResponse<>(true, "Password reset successfully", null);
    }

    /**
     * Check if the login state is valid by verifying the email in Redis.
     * 
     * @param email the user's email
     * @return true if the login state is valid, false otherwise
     */
    private boolean checkLoginValid(String email) {
        String key = "loginState:" + email;
        logger.info("Retrieving key from Redis: " + key);
    
        String isLoginValidValue = (String) redisTemplate.opsForValue().get(key);
        logger.info("Login state for email {} is: {}", email, isLoginValidValue);
    
        if (isLoginValidValue == null || !(isLoginValidValue.equals("true"))) {
            logger.warn("Login state is invalid or expired for email: {}", email);
            return false;
        }
        return true;
    }

    /**
     * Authenticate a user using the AuthenticationManager and retrieve their user details.
     * 
     * @param loginDtoReq the login request containing email and password
     * @return the authenticated user entity
     * @throws InvalidInputException if the user is not found
     */
    private User authenticate (LoginDtoRequest loginDtoReq) {
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

    /**
     * Handle failed login attempts for the given user.
     * If failed attempts reach 5, lock the account and send an account-locked event.
     * 
     * @param user the user entity
     * @return true if the account has been locked, false otherwise
     */
    private boolean handleFailedAttempts(User user) {
        Integer failedAttempted = user.getAttemptedCount() + 1;
        user.setAttemptedCount(failedAttempted);

        if (failedAttempted >= 5) {
            user.setLocked(true);
            userRepository.save(user);

            // Build and send account locked event
            EmailRequestEvent accountLockedEvent = notificationService.buildEmailRequestEvent(user);
            otpKafkaProducer.sendMessage(
                accountLockedEvent, 
                kafkaTopicsConfig.getProducedTopic("user.account.locked").getName()
            );

            logger.info("Account locked event sent for user: {}", user.getEmail());
            return true;
        }

        userRepository.save(user);
        return false;
    }


}
