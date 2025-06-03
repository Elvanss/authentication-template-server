package com.auth.ms_user.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.ms_user.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {
    
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // @RequestMapping(value = "/v1/profile", method = RequestMethod.GET)
    // @Description("Get user profile details.")

    // @RequestMapping(value = "/v1/update-profile", method = RequestMethod.PUT)
    // @Description("Update user profile details.")

    // @RequestMapping(value = "/v1/activate-account", method = RequestMethod.POST)
    // @Description("Activate the user account with the provided activation code.")

    // @RequestMapping(value = "/v1/deactivate-account", method = RequestMethod.POST)
    // @Description("Deactivate the user account with the provided deactivation code.")


    
}
