package com.template.shared.api.user.req;

public class VerifyOtpRequest {
    private String email;
    private Integer otp;

    public VerifyOtpRequest() {}
    
    public VerifyOtpRequest(String email, Integer otp) {
        this.email = email;
        this.otp = otp;
    }


    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Integer getOtp() {
        return this.otp;
    }

    public void setOtp(Integer otp) {
        this.otp = otp;
    }

}
