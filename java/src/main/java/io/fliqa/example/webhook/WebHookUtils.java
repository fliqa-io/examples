package io.fliqa.example.webhook;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.*;
import java.security.*;
import java.util.*;

/**
 * Signature is created by using SHA256 to create a hash
 * Input is: {time-in-epoch-seconds}.{hookUrl}.{recieved_body}
 * Header holds: {time-in-epoch-seconds} and created hash as: t={time-in-epoch-seconds},v={hashHexEncoded}
 * alternately header can hold old and new verification if secret was changed within 24h
 * as: t={time-in-epoch-seconds},v={hashHexEncoded},v0={oldHashHexEncoded}
 */
public class WebHookUtils {

    private static final String DIGEST = "HmacSHA256";
    private static final String TIME_STAMP = "t=";
    private static final String VERIFICATION = "v=";
    private static final String OLD_VERIFICATION = "v0=";

    public static boolean checkSignature(String signature, String secret, String oldSecret, String hookUrl, String body) {

        // Split signature to t={time},v={verification},v0={old_verification}
        String[] timeAndSignature = signature.split(",");
        if (timeAndSignature.length < 2 || timeAndSignature.length > 3) {
            throw new IllegalArgumentException(String.format("Invalid signature, expected time and verification but got: '%s'!", signature));
        }

        Long time = getSignatureTime(timeAndSignature);

        String oldVerification = null;
        String oldCompare = null;
        if (timeAndSignature.length == 3) { // there is the old signature present (double check)
            oldVerification = getOldSignatureVerification(timeAndSignature);
            oldCompare = sign(oldSecret, time.toString(), hookUrl, body);
        }

        String verification = getSignatureVerification(timeAndSignature);
        String compare = sign(secret, time.toString(), hookUrl, body);

        return verification.equals(compare) || (oldVerification != null && oldVerification.equals(oldCompare));
    }

    protected static String sign(String secret, String time, String hookUrl, String content) {
        String input = String.format("%s.%s.%s", time, hookUrl, content);

        try {
            Mac mac = Mac.getInstance(DIGEST);
            mac.init(new SecretKeySpec(secret.getBytes(), DIGEST));
            return toHexString(mac.doFinal(input.getBytes()));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // Failed to create SHA signature!
            return "";
        }
    }

    public static String toHexString(byte[] arg) {
        return String.format("%x", new BigInteger(1, arg));
    }

    protected static Long getSignatureTime(String[] timeAndSignature) {
        Optional<String> found = Arrays.stream(timeAndSignature).filter(item -> item.toLowerCase().startsWith(TIME_STAMP)).findFirst();
        if (found.isPresent()) {
            try {
                return Long.parseLong(found.get().substring(TIME_STAMP.length()));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(String.format("Signature time (%s<timestamp>) invalid: '%s'!", TIME_STAMP, found.get()));
            }
        }

        throw new IllegalArgumentException(String.format("Signature time (%s<timestamp>) missing!", TIME_STAMP));
    }

    protected static String getSignatureVerification(String[] timeAndSignature) {
        Optional<String> found = Arrays.stream(timeAndSignature).filter(item -> item.toLowerCase().startsWith(VERIFICATION)).findFirst();
        return found.map(s -> s.substring(VERIFICATION.length())).orElseThrow(() -> new IllegalArgumentException(String.format("Signature verification (%s<verification>) missing!", VERIFICATION)));
    }

    protected static String getOldSignatureVerification(String[] timeAndSignature) {
        Optional<String> found = Arrays.stream(timeAndSignature).filter(item -> item.toLowerCase().startsWith(OLD_VERIFICATION)).findFirst();
        return found.map(s -> s.substring(OLD_VERIFICATION.length())).orElseThrow(() -> new IllegalArgumentException(String.format("Signature old verification (%s<verification>) missing!", OLD_VERIFICATION)));
    }
}