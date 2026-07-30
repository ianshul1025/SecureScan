package com.anshul.securescan.controller;

import com.anshul.securescan.dto.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    @GetMapping("/health")
    public ApiResponse<String> health() {
        return ApiResponse.success("SecureScan Backend is Running", "SecureScan Backend is Running 🚀");
    }
}