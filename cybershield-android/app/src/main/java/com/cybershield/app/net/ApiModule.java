package com.cybershield.app.net;

import android.content.Context;

import com.cybershield.app.BuildConfig;
import com.cybershield.app.data.SecureStore;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

/**
 * Builds the Retrofit client. Attaches the stored bearer token to every
 * request. Unlike earlier builds there are NO hard-coded credentials - the user
 * signs in through {@code AuthActivity} and the token is kept in
 * {@link SecureStore} (EncryptedSharedPreferences).
 */
public class ApiModule {

    private final SecureStore store;
    private final CyberShieldApi api;

    public ApiModule(Context ctx) {
        this.store = new SecureStore(ctx.getApplicationContext());

        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(BuildConfig.DEBUG
                ? HttpLoggingInterceptor.Level.BASIC
                : HttpLoggingInterceptor.Level.NONE);

        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(chain -> {
                    Request original = chain.request();
                    String token = store.token();
                    if (token != null && !original.url().encodedPath().startsWith("/auth/")) {
                        original = original.newBuilder()
                                .header("Authorization", "Bearer " + token)
                                .header("X-Client", "android")
                                .build();
                    } else {
                        original = original.newBuilder().header("X-Client", "android").build();
                    }
                    okhttp3.Response resp = chain.proceed(original);
                    if (resp.code() == 401 && token != null
                            && !original.url().encodedPath().startsWith("/auth/")) {
                        // token expired/invalid - drop it; UI will route to sign-in
                        store.clearToken();
                    }
                    return resp;
                })
                .addInterceptor(logging)
                .build();

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(BuildConfig.API_BASE_URL)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build();

        this.api = retrofit.create(CyberShieldApi.class);
    }

    public CyberShieldApi api() {
        return api;
    }

    public SecureStore store() {
        return store;
    }
}
