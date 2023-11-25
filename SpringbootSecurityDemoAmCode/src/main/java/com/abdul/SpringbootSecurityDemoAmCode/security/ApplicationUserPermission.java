package com.abdul.SpringbootSecurityDemoAmCode.security;

public enum ApplicationUserPermission {

//    Create permissions
    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

//    Create a permission method and create a constructor and a getter
    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
