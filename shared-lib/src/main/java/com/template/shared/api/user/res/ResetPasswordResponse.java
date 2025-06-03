package com.template.shared.api.user.res;

public class ResetPasswordResponse {
    private boolean isSuccess;

    public ResetPasswordResponse() {}

    public ResetPasswordResponse(boolean isSuccess) {
        this.isSuccess = isSuccess;
    }

    public boolean isSuccess() {
        return isSuccess;
    }

    public void setSuccess(boolean isSuccess) {
        this.isSuccess = isSuccess;
    }
}
