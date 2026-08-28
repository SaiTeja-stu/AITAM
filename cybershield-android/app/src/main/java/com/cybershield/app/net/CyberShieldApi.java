package com.cybershield.app.net;

import com.cybershield.app.net.dto.AnalyzeRequest;
import com.cybershield.app.net.dto.AnalyzeResponse;
import com.cybershield.app.net.dto.ReportRequest;
import com.cybershield.app.net.dto.TokenResponse;

import java.util.Map;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;

public interface CyberShieldApi {

    // ---- auth ----
    @POST("auth/register")
    Call<Map<String, String>> register(@Body Map<String, String> body);

    @POST("auth/verify-email")
    Call<Map<String, String>> verifyEmail(@Body Map<String, String> body);

    @POST("auth/resend-verification")
    Call<Map<String, String>> resendVerification(@Body Map<String, String> body);

    @POST("auth/login")
    Call<TokenResponse> login(@Body Map<String, String> body);

    @POST("auth/forgot-password")
    Call<Map<String, String>> forgotPassword(@Body Map<String, String> body);

    @POST("auth/reset-password")
    Call<Map<String, String>> resetPassword(@Body Map<String, String> body);

    // ---- core ----
    @POST("api/v1/analyze")
    Call<AnalyzeResponse> analyze(@Body AnalyzeRequest request);

    @POST("api/v1/report")
    Call<Map<String, String>> report(@Body ReportRequest request);

    @GET("api/v1/education/modules")
    Call<Object> educationModules();
}
