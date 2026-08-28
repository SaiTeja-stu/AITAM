package com.cybershield.app.data;

import android.os.Handler;
import android.os.Looper;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.net.dto.TokenResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import retrofit2.Response;

/** Calls the /auth/* endpoints off the main thread and posts results back. */
public class AuthRepository {

    public interface Cb {
        void ok(String message);
        void fail(String message);
    }

    public interface TokenCb {
        void token(String jwt);
        void needsVerification();
        void fail(String message);
    }

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final SecureStore store;

    public AuthRepository() {
        this.store = CyberShieldApp.get().api().store();
    }

    public void register(String email, String username, String displayName, String password, Cb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("email", email);
        b.put("username", username);
        b.put("displayName", displayName);
        b.put("password", password);
        call(() -> CyberShieldApp.get().api().api().register(b).execute(), cb,
                "Check your email for a 6-digit code.");
    }

    public void verifyEmail(String email, String code, Cb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("email", email);
        b.put("code", code);
        call(() -> CyberShieldApp.get().api().api().verifyEmail(b).execute(), cb,
                "Email verified. You can sign in now.");
    }

    public void resend(String email, Cb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("email", email);
        call(() -> CyberShieldApp.get().api().api().resendVerification(b).execute(), cb,
                "A new code is on its way.");
    }

    public void forgot(String email, Cb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("email", email);
        call(() -> CyberShieldApp.get().api().api().forgotPassword(b).execute(), cb,
                "If that email is registered, a reset code has been sent.");
    }

    public void reset(String email, String code, String newPassword, Cb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("email", email);
        b.put("code", code);
        b.put("newPassword", newPassword);
        call(() -> CyberShieldApp.get().api().api().resetPassword(b).execute(), cb,
                "Password updated. Sign in with your new password.");
    }

    public void login(String login, String password, TokenCb cb) {
        Map<String, String> b = new HashMap<>();
        b.put("login", login);
        b.put("password", password);
        io.execute(() -> {
            try {
                Response<TokenResponse> r = CyberShieldApp.get().api().api().login(b).execute();
                if (r.isSuccessful() && r.body() != null && r.body().accessToken != null) {
                    store.setTokens(r.body().accessToken, r.body().refreshToken);
                    if (login.contains("@")) store.setEmail(login);
                    main.post(() -> cb.token(r.body().accessToken));
                } else if (r.code() == 403) {
                    main.post(cb::needsVerification);
                } else if (r.code() == 429) {
                    main.post(() -> cb.fail("Too many attempts. Try again later."));
                } else {
                    main.post(() -> cb.fail("Invalid credentials."));
                }
            } catch (Exception e) {
                main.post(() -> cb.fail("Network error. Is the backend reachable?"));
            }
        });
    }

    public void logout() {
        // wipe locally right away; revoke on the server best-effort
        String rt = store.refreshToken();
        store.clearSession();
        io.execute(() -> {
            try {
                if (rt != null) {
                    java.util.Map<String, String> b = new java.util.HashMap<>();
                    b.put("refreshToken", rt);
                    CyberShieldApp.get().api().api().logout(b).execute();
                }
            } catch (Exception ignored) {
            }
        });
    }

    private interface ApiCall {
        Response<Map<String, String>> run() throws Exception;
    }

    private void call(ApiCall c, Cb cb, String okFallback) {
        io.execute(() -> {
            try {
                Response<Map<String, String>> r = c.run();
                String msg = r.body() != null && r.body().get("message") != null
                        ? r.body().get("message") : okFallback;
                if (r.isSuccessful() || r.code() == 202) {
                    main.post(() -> cb.ok(msg));
                } else {
                    String err = r.body() != null && r.body().get("message") != null
                            ? r.body().get("message") : "That didn't work (" + r.code() + ").";
                    main.post(() -> cb.fail(err));
                }
            } catch (Exception e) {
                main.post(() -> cb.fail("Network error. Is the backend reachable?"));
            }
        });
    }
}
