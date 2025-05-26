package com.template.shared.api.user.res;

import com.template.shared.api.user.event.OtpRequestEvent;

public class CredentialResponse {
    private boolean flag;
    private String message;
    private OtpRequestEvent otpRequestEvent;


    public boolean isFlag() {
        return this.flag;
    }

    public boolean getFlag() {
        return this.flag;
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public OtpRequestEvent getOtpRequestEvent() {
        return this.otpRequestEvent;
    }

    public void setOtpRequestEvent(OtpRequestEvent otpRequestEvent) {
        this.otpRequestEvent = otpRequestEvent;
    }

}
