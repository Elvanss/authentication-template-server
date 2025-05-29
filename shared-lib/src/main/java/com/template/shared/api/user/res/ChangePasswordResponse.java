package com.template.shared.api.user.res;

public class ChangePasswordResponse {
    private boolean isSuccess;
    private Integer attemptCount;

    public ChangePasswordResponse() {}

    public ChangePasswordResponse(boolean isSuccess, Integer attemptCount) {
        this.isSuccess = isSuccess;
        this.attemptCount = attemptCount;
    }

    public boolean isSuccess() {
        return isSuccess;
    }

    public void setSuccess(boolean success) {
        isSuccess = success;
    }

    public Integer getAttemptCount() {
        return attemptCount;
    }

    public void setAttemptCount(Integer attemptCount) {
        this.attemptCount = attemptCount;
    }
}
