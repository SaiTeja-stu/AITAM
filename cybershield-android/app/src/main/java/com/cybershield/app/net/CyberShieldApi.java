package com.cybershield.app.net;

import com.cybershield.app.net.dto.AnalyzeRequest;
import com.cybershield.app.net.dto.AnalyzeResponse;
import com.cybershield.app.net.dto.Page;
import com.cybershield.app.net.dto.ReportRequest;
import com.cybershield.app.net.dto.TokenResponse;
import com.cybershield.app.ui.EduAdapter;

import java.util.List;
import java.util.Map;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Path;
import retrofit2.http.Query;

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

    @POST("auth/refresh")
    Call<TokenResponse> refresh(@Body Map<String, String> body);

    @POST("auth/logout")
    Call<Map<String, String>> logout(@Body Map<String, String> body);

    @POST("auth/forgot-password")
    Call<Map<String, String>> forgotPassword(@Body Map<String, String> body);

    @POST("auth/reset-password")
    Call<Map<String, String>> resetPassword(@Body Map<String, String> body);

    @GET("auth/me")
    Call<Map<String, Object>> me();

    // ---- core ----
    @POST("api/v1/analyze")
    Call<AnalyzeResponse> analyze(@Body AnalyzeRequest request);

    @POST("api/v1/report")
    Call<Map<String, String>> report(@Body ReportRequest request);

    @GET("api/v1/education/modules")
    Call<List<EduAdapter.Module>> educationModules();

    @GET("api/v1/history")
    Call<Map<String, Object>> myHistory(@Query("page") int page, @Query("size") int size);

    // ---- admin (dashboard) ----
    @GET("api/v1/stats")
    Call<Map<String, Object>> stats();

    @GET("api/v1/stats/trends")
    Call<Map<String, Object>> trends();

    @GET("api/v1/admin/scans")
    Call<Page<Page.ScanItem>> adminScans(@Query("level") String level,
                                         @Query("page") int page, @Query("size") int size);

    @GET("api/v1/admin/reports")
    Call<Page<Page.ReportItem>> adminReports(@Query("status") String status,
                                             @Query("page") int page, @Query("size") int size);

    @POST("api/v1/admin/reports/{id}/confirm")
    Call<Map<String, Object>> confirmReport(@Path("id") String id);

    @POST("api/v1/admin/reports/{id}/reject")
    Call<Map<String, Object>> rejectReport(@Path("id") String id);
}
