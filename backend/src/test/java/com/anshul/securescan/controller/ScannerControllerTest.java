package com.anshul.securescan.controller;

import com.anshul.securescan.dto.ApiResponse;
import com.anshul.securescan.dto.ScanResponse;
import com.anshul.securescan.exception.GlobalExceptionHandler;
import com.anshul.securescan.exception.InvalidScanProfileException;
import com.anshul.securescan.service.ScannerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ScannerControllerTest {

    private MockMvc mockMvc;
    private ScannerService scannerService;

    @BeforeEach
    void setUp() {
        scannerService = Mockito.mock(ScannerService.class);
        ScannerController controller = new ScannerController(scannerService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void scanWebsiteAcceptsValidRequestAndReturnsSuccess() throws Exception {
        ScanResponse response = new ScanResponse("https://example.com", "SUCCESS");
        response.setHost("example.com");
        response.setScanProfile("QUICK");

        Mockito.when(scannerService.scan(any())).thenReturn(ApiResponse.success("Scan completed successfully", response));

        mockMvc.perform(post("/api/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"https://example.com\",\"scanProfile\":\"QUICK\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.scanProfile").value("QUICK"));
    }

    @Test
    void scanWebsiteReturns400ForInvalidScanProfile() throws Exception {
        Mockito.when(scannerService.scan(any())).thenThrow(new InvalidScanProfileException("Unsupported scan profile: INVALID_PROFILE"));

        mockMvc.perform(post("/api/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"https://example.com\",\"scanProfile\":\"INVALID_PROFILE\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Unsupported scan profile: INVALID_PROFILE"));
    }

    @Test
    void scanWebsiteReturns400ForBlankUrl() throws Exception {
        mockMvc.perform(post("/api/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"\"}"))
                .andExpect(status().isBadRequest());
    }
}
