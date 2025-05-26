package com.template.shared.api.user.res;

public class OtpResponse {
    private String otpId;
    private String email;
    private Integer otp;
    private boolean expired;

    public OtpResponse(String otpId, String email, Integer otp, boolean expired) {
        this.otpId = otpId;
        this.email = email;
        this.otp = otp;
        this.expired = expired;
    }


    public String getOtpId() {
        return this.otpId;
    }

    public void setOtpId(String otpId) {
        this.otpId = otpId;
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

    public boolean isExpired() {
        return this.expired;
    }

    public boolean getExpired() {
        return this.expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

}
