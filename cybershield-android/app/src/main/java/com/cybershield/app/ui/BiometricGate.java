package com.cybershield.app.ui;

import android.util.Log;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

/**
 * Fingerprint / face / device-credential unlock. Used to gate the app once the
 * user is signed in AND has explicitly turned biometric lock on.
 *
 * It never finishes the activity on its own - a failed/cancelled prompt just
 * reports back and the caller decides (we keep an "Unlock" button visible so a
 * logged-in user is never locked out of their own app).
 */
public final class BiometricGate {

    private static final String TAG = "BiometricGate";

    public interface Result {
        void onUnlocked();
        void onFailedOrCancelled();
    }

    private static final int ALLOWED =
            BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL;

    private BiometricGate() {}

    /** True only if the device can actually prompt right now (something enrolled). */
    public static boolean available(FragmentActivity a) {
        try {
            return BiometricManager.from(a).canAuthenticate(ALLOWED)
                    == BiometricManager.BIOMETRIC_SUCCESS;
        } catch (Exception e) {
            return false;
        }
    }

    public static void prompt(FragmentActivity activity, Result cb) {
        try {
            BiometricPrompt prompt = new BiometricPrompt(activity,
                    ContextCompat.getMainExecutor(activity),
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            cb.onUnlocked();
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            Log.w(TAG, "biometric error " + errorCode + ": " + errString);
                            cb.onFailedOrCancelled();
                        }
                    });

            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock Cyber Shield")
                    .setSubtitle("Confirm it's you to open the app")
                    .setAllowedAuthenticators(ALLOWED)
                    .build();

            prompt.authenticate(info);
        } catch (Exception e) {
            Log.w(TAG, "biometric prompt failed to start", e);
            cb.onFailedOrCancelled();
        }
    }
}
