package com.cybershield.app.ui;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.data.AuthRepository;
import com.cybershield.app.databinding.ActivityAuthBinding;

/**
 * One screen, several modes: sign-in, sign-up, verify-email, forgot-password,
 * reset-password. Talks to the backend /auth/* endpoints via {@link AuthRepository}.
 */
public class AuthActivity extends AppCompatActivity {

    private enum Mode { SIGN_IN, SIGN_UP, VERIFY, FORGOT, RESET }

    private ActivityAuthBinding b;
    private final AuthRepository auth = new AuthRepository();
    private Mode mode = Mode.SIGN_IN;
    private String pendingEmail = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityAuthBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.btnPrimary.setOnClickListener(v -> submit());
        b.btnSecondary.setOnClickListener(v ->
                setMode(mode == Mode.SIGN_IN ? Mode.SIGN_UP : Mode.SIGN_IN));
        b.btnForgot.setOnClickListener(v -> {
            if (mode == Mode.VERIFY) {
                auth.resend(pendingEmail, cb(() -> {}));
            } else {
                setMode(Mode.FORGOT);
            }
        });

        // Password-reset deep link from the email: cybershield://reset?email=..&code=..
        android.net.Uri data = getIntent() == null ? null : getIntent().getData();
        if (data != null && "cybershield".equals(data.getScheme()) && "reset".equals(data.getHost())) {
            pendingEmail = data.getQueryParameter("email") == null ? "" : data.getQueryParameter("email");
            String code = data.getQueryParameter("code");
            setMode(Mode.RESET);
            if (code != null) b.etCode.setText(code);
            return;
        }

        setMode(Mode.SIGN_IN);
    }

    private void setMode(Mode m) {
        mode = m;
        b.message.setVisibility(View.GONE);
        boolean signup = m == Mode.SIGN_UP;
        boolean verify = m == Mode.VERIFY;
        boolean forgot = m == Mode.FORGOT;
        boolean reset = m == Mode.RESET;

        b.tilLogin.setVisibility(verify || reset ? View.GONE : View.VISIBLE);
        b.tilLogin.setHint(signup || forgot ? "Email" : "Email or username");
        b.tilUsername.setVisibility(signup ? View.VISIBLE : View.GONE);
        b.tilPassword.setVisibility(forgot || verify ? View.GONE : View.VISIBLE);
        b.tilPassword.setHint(reset ? "New password" : "Password");
        b.tilCode.setVisibility(verify || reset ? View.VISIBLE : View.GONE);

        switch (m) {
            case SIGN_IN -> set("Sign in", "Use your Cyber Shield account.", "Sign in", "Create an account", true);
            case SIGN_UP -> set("Create account", "We'll email a 6-digit code to confirm it's your address.", "Create account", "I already have an account", false);
            case VERIFY -> {
                set("Confirm your account",
                        "We emailed a 6-digit code to " + pendingEmail + ". Enter it to finish creating your account.",
                        "Confirm account", "Back to sign in", false);
                b.btnForgot.setVisibility(View.VISIBLE);
                b.btnForgot.setText("Resend code");
            }
            case FORGOT -> set("Reset password", "We'll email you a 6-digit reset code.", "Send code", "Back to sign in", false);
            case RESET -> set("Set new password", "Enter the code from your email and a new password.", "Update password", "Back to sign in", false);
        }
    }

    private void set(String title, String sub, String primary, String secondary, boolean showForgot) {
        b.title.setText(title);
        b.subtitle.setText(sub);
        b.btnPrimary.setText(primary);
        b.btnSecondary.setText(secondary);
        b.btnForgot.setText("Forgot password?");
        b.btnForgot.setVisibility(showForgot ? View.VISIBLE : View.GONE);
    }

    private void submit() {
        String login = text(b.etLogin);
        String username = text(b.etUsername);
        String password = text(b.etPassword);
        String code = text(b.etCode);
        b.btnPrimary.setEnabled(false);

        switch (mode) {
            case SIGN_IN -> auth.login(login, password, new AuthRepository.TokenCb() {
                @Override public void token(String jwt) { goToApp(); }
                @Override public void needsVerification() {
                    pendingEmail = login; setMode(Mode.VERIFY); msg("We sent you a new code — check your email.", false);
                }
                @Override public void fail(String m) { msg(m, true); }
            });

            case SIGN_UP -> {
                if (!login.contains("@") || username.length() < 3 || password.length() < 12) {
                    msg("Enter a valid email, a username (3+ chars) and a password (12+ chars).", true);
                    return;
                }
                pendingEmail = login;
                auth.register(login, username, username, password, cb(() -> setMode(Mode.VERIFY)));
            }

            case VERIFY -> {
                if (code.length() != 6) { msg("Enter the 6-digit code.", true); return; }
                auth.verifyEmail(pendingEmail, code, cb(() -> setMode(Mode.SIGN_IN)));
            }

            case FORGOT -> {
                if (!login.contains("@")) { msg("Enter your account email.", true); return; }
                pendingEmail = login;
                auth.forgot(login, cb(() -> setMode(Mode.RESET)));
            }

            case RESET -> {
                if (code.length() != 6 || password.length() < 12) {
                    msg("Enter the 6-digit code and a new password (12+ chars).", true);
                    return;
                }
                auth.reset(pendingEmail, code, password, cb(() -> setMode(Mode.SIGN_IN)));
            }
        }
    }

    private AuthRepository.Cb cb(Runnable onOk) {
        return new AuthRepository.Cb() {
            @Override public void ok(String m) {
                onOk.run();               // switch screen first (setMode clears the message)
                msg(m, false);            // then show the confirmation on the new screen
                b.btnPrimary.setEnabled(true);
            }
            @Override public void fail(String m) { msg(m, true); }
        };
    }

    private void msg(String m, boolean error) {
        b.btnPrimary.setEnabled(true);
        b.message.setVisibility(View.VISIBLE);
        b.message.setText(m);
        b.message.setTextColor(getColor(error ? com.cybershield.app.R.color.risk_malicious
                : com.cybershield.app.R.color.risk_safe));
    }

    private void goToApp() {
        startActivity(new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));
        finish();
    }

    private static String text(com.google.android.material.textfield.TextInputEditText e) {
        CharSequence c = e.getText();
        return c == null ? "" : c.toString().trim();
    }
}
