package com.auth.ms_user.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "${domain.service.ms-notification.name}", url = "${domain.service.ms-notification.url}")
public interface OtpServiceClient {

    @PostMapping("/otp/verify") 
    boolean verifyOtp(@RequestParam("email") String email, @RequestParam("otp") Integer otp);

    @DeleteMapping("/otp/delete")
    void deleteOtp(@RequestParam("email") String email);
}
