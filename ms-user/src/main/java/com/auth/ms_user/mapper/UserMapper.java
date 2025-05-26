package com.auth.ms_user.mapper;

import org.springframework.stereotype.Component;

import com.auth.ms_user.domain.User;
import com.template.shared.api.user.res.UserResponse;

@Component
public class UserMapper {
    public UserResponse toUserDto(User user) {
        UserResponse userDto = new UserResponse();
        userDto.setName(user.getName());
        userDto.setEmail(user.getEmail());
        userDto.setDateOfBirth(user.getDateOfBirth());
        userDto.setProfileImage(user.getProfileImage());
        return userDto;
    }
}
