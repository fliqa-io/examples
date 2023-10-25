package io.fliqa.example.webhook;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.*;
import java.security.*;
import java.util.*;

/**
 * Signature is created by using SHA256 to create a hash
 * Input is:
 * - {time-in-epoch-seconds}.{hookUrl}.{recieved_body}
 * X-Fliqa-Signature header holds: {time-in-epoch-seconds} and created hash in format:
 *     t={time-in-epoch-seconds},v={hashHexEncoded}
 * alternately header can hold old and new verification if secret was changed within 24h in format:
 *     t={time-in-epoch-seconds},v={hashHexEncoded},v0={oldHashHexEncoded}
 */
public class WebHookUtils {

    private static final String DIGEST = "HmacSHA256";
    private static final String TIME_STAMP = "t=";
    private static final String VERIFICATION = "v=";
    private static final String OLD_VERIFICATION = "v0=";

    /**
     * Checks provided signature against know data
     *
     * @param signature provided as is (X-Fliqa-Signature header value)
     * @param secret    internal WebHook secret
     * @param oldSecret internal WebHook old-secret (if secret has been altered)
     * @param hookUrl   called hook-url (your hook URL endpoint)
     * @param body      posted JSON body
     * @return true if signature is valid, false otherwise
     */
    public static boolean checkSignature(String signature, String secret, String oldSecret, String hookUrl, String body) {

        // Split signature to t={time} v={verification} and v0={old_verification}
        String[] timeAndVerification = signature.split(",");
        if (timeAndVerification.length < 2 || timeAndVerification.length > 3) {
            throw new IllegalArgumentException(String.format("Invalid signature, expected time and verification but got: '%s'!", signature));
        }

        Long time = getSignatureTime(timeAndVerification);

        String oldVerification = null;
        String oldCompare = null;
        if (timeAndVerification.length == 3) { // there is the old signature present (double check)
            oldVerification = getOldSignatureVerification(timeAndVerification);
            oldCompare = sign(oldSecret, time.toString(), hookUrl, body);
        }

        String verification = getSignatureVerification(timeAndVerification);
        String compare = sign(secret, time.toString(), hookUrl, body);

        return verification.equals(compare) || (oldVerification != null && oldVerification.equals(oldCompare));
    }

    /**
     * Generates signature from given secret, time and payload
     *
     * @param secret  internal hook secret
     * @param time    timestamp in seconds as string
     * @param hookUrl called hook URL
     * @param body    JSON post payload
     * @return generated SHA-256 signature in Hex format
     */
    protected static String sign(String secret, String time, String hookUrl, String body) {
        String input = String.format("%s.%s.%s", time, hookUrl, body);

        try {
            Mac mac = Mac.getInstance(DIGEST);
            mac.init(new SecretKeySpec(secret.getBytes(), DIGEST));
            return toHexString(mac.doFinal(input.getBytes()));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // Failed to create SHA signature!
            return "";
        }
    }

    /**
     * Converts byte array to hex string
     *
     * @param content byte array
     * @return hex representation of byte array
     */
    public static String toHexString(byte[] content) {
        return String.format("%x", new BigInteger(1, content));
    }

    /**
     * Tries to extract time stamp from signature header
     *
     * @param timeAndVerification X-Fliqa-Signature header split by ','
     * @return timestamp if present
     * @throws IllegalArgumentException if timestamp is not present
     */
    protected static Long getSignatureTime(String[] timeAndVerification) {
        Optional<String> found = Arrays.stream(timeAndVerification).filter(item -> item.toLowerCase().startsWith(TIME_STAMP)).findFirst();
        if (found.isPresent()) {
            try {
                return Long.parseLong(found.get().substring(TIME_STAMP.length())); // we expect number (we do not check if it is a possible time!)
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(String.format("Signature time (%s<timestamp>) invalid: '%s'!", TIME_STAMP, found.get()));
            }
        }

        throw new IllegalArgumentException(String.format("Signature time (%s<timestamp>) missing!", TIME_STAMP));
    }

    /**
     * Tries to extract verification from signature header
     *
     * @param timeAndVerification X-Fliqa-Signature header split by ','
     * @return verification if present
     * @throws IllegalArgumentException if verification is not present
     */
    protected static String getSignatureVerification(String[] timeAndVerification) {
        Optional<String> found = Arrays.stream(timeAndVerification).filter(item -> item.toLowerCase().startsWith(VERIFICATION)).findFirst();
        return found.map(s -> s.substring(VERIFICATION.length())).orElseThrow(
            () -> new IllegalArgumentException(String.format("Signature verification (%s<verification>) missing!", VERIFICATION))
        );
    }

    /**
     * Tries to extract old verification from signature header
     *
     * @param timeAndVerification X-Fliqa-Signature header split by ','
     * @return verification if present
     * @throws IllegalArgumentException if verification is not present
     */
    protected static String getOldSignatureVerification(String[] timeAndVerification) {
        Optional<String> found = Arrays.stream(timeAndVerification).filter(item -> item.toLowerCase().startsWith(OLD_VERIFICATION)).findFirst();
        return found.map(s -> s.substring(OLD_VERIFICATION.length())).orElseThrow(
            () -> new IllegalArgumentException(String.format("Signature old verification (%s<verification>) missing!", OLD_VERIFICATION))
        );
    }
}