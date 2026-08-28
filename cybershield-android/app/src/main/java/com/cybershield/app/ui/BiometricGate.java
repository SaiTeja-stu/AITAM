package com.cybershield.app.ui;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

/**
 * Fingerprint / face / device-credential unlock. Used to gate the app once the
 * user is signed in and has biometric lock enabled.
 */
public final class BiometricGate {

    public interface Result {
        void onUnlocked();
        void onFailedOrCancelled();
    }

    private static final int ALLOWED =
            BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL;

    private BiometricGate() {}

    /** True if the device can do biometric OR device-credential auth. */
    public static boolean available(FragmentActivity a) {
        int r = BiometricManager.from(a).canAuthenticate(ALLOWED);
        return r == BiometricManager.BIOMETRIC_SUCCESS
                || r == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED;
    }

    public static void prompt(FragmentActivity activity, Result cb) {
        BiometricPrompt prompt = new BiometricPrompt(activity,
                ContextCompat.getMainExecutor(activity),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        cb.onUnlocked();
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        cb.onFailedOrCancelled();
                    }
                });

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Cyber Shield")
                .setSubtitle("Confirm it's you to open the app")
                .setAllowedAuthenticators(ALLOWED)
                .build();

        prompt.authenticate(info);
    }
}
