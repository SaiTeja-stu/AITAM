package com.cybershield.app.net;

import android.content.Context;

import com.cybershield.app.BuildConfig;
import com.cybershield.app.data.SecureStore;
import com.cybershield.app.net.dto.TokenResponse;

import java.util.HashMap;
import java.util.Map;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

/**
 * Retrofit client. The base URL is read from {@link SecureStore} on EVERY
 * request (via a rewrite interceptor) so the user can point the app at their
 * PC's LAN IP / emulator / adb-reverse from the in-app "Server" setting without
 * rebuilding.
 *
 * On a 401 the expired access token is swapped for a fresh one using the
 * long-lived refresh token, then the request is retried once.
 */
public class ApiModule {

    private final SecureStore store;
    private final CyberShieldApi api;
    private final CyberShieldApi bareApi;   // no auth interceptor, for the refresh call itself
    private final Object refreshLock = new Object();

    public ApiModule(Context ctx) {
        this.store = new SecureStore(ctx.getApplicationContext());

        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(BuildConfig.DEBUG
                ? HttpLoggingInterceptor.Level.BASIC
                : HttpLoggingInterceptor.Level.NONE);

        // rewrites scheme/host/port of every request to the currently-configured base URL
        okhttp3.Interceptor rebase = chain -> {
            HttpUrl base = HttpUrl.parse(store.baseUrl());
            Request req = chain.request();
            if (base == null) return chain.proceed(req);
            HttpUrl newUrl = req.url().newBuilder()
                    .scheme(base.scheme())
                    .host(base.host())
                    .port(base.port())
                    .build();
            return chain.proceed(req.newBuilder().url(newUrl).build());
        };

        OkHttpClient bareClient = new OkHttpClient.Builder()
                .addInterceptor(rebase)
                .addInterceptor(logging)
                .build();
        this.bareApi = new Retrofit.Builder()
                .baseUrl(BuildConfig.API_BASE_URL)
                .client(bareClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(CyberShieldApi.class);

        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(rebase)
                .addInterceptor(chain -> {
                    Request original = chain.request();
                    boolean isAuthPath = original.url().encodedPath().startsWith("/auth/");
                    Request.Builder rb = original.newBuilder().header("X-Client", "android");
                    String access = store.token();
                    if (access != null && !isAuthPath) {
                        rb.header("Authorization", "Bearer " + access);
                    }
                    okhttp3.Response resp = chain.proceed(rb.build());

                    if (resp.code() == 401 && !isAuthPath) {
                        resp.close();
                        String fresh = tryRefresh();
                        if (fresh != null) {
                            return chain.proceed(original.newBuilder()
                                    .header("Authorization", "Bearer " + fresh)
                                    .header("X-Client", "android")
                                    .build());
                        }
                        return new okhttp3.Response.Builder()
                                .request(original).protocol(okhttp3.Protocol.HTTP_1_1)
                                .code(401).message("session expired")
                                .body(okhttp3.ResponseBody.create(null, new byte[0]))
                                .build();
                    }
                    return resp;
                })
                .addInterceptor(logging)
                .build();

        this.api = new Retrofit.Builder()
                .baseUrl(BuildConfig.API_BASE_URL)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(CyberShieldApi.class);
    }

    public CyberShieldApi api() {
        return api;
    }

    public SecureStore store() {
        return store;
    }

    public String tryRefresh() {
        synchronized (refreshLock) {
            String rt = store.refreshToken();
            if (rt == null) return null;
            try {
                Map<String, String> body = new HashMap<>();
                body.put("refreshToken", rt);
                Response<TokenResponse> r = bareApi.refresh(body).execute();
                if (r.isSuccessful() && r.body() != null && r.body().accessToken != null) {
                    store.setTokens(r.body().accessToken, r.body().refreshToken);
                    return r.body().accessToken;
                }
                store.clearSession();
                return null;
            } catch (Exception e) {
                return null;
            }
        }
    }

    public void signOut() {
        String rt = store.refreshToken();
        store.clearSession();
        if (rt != null) {
            try {
                Map<String, String> body = new HashMap<>();
                body.put("refreshToken", rt);
                bareApi.logout(body).execute();
            } catch (Exception ignored) {
            }
        }
    }
}
