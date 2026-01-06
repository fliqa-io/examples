<?php

class WebHookUtils
{
    private const DIGEST = 'sha256';

    public static function checkSignature(string $signature, string $secret, string $oldSecret, string $hookUrl, string $body): bool
    {
        // Split signature to t={time},v={verification},v0={old_verification}
        $parts = explode(',', $signature);
        if (count($parts) < 2 || count($parts) > 3) {
            throw new InvalidArgumentException(sprintf(
                "Invalid signature, expected time and verification but got: '%s'!",
                $signature
            ));
        }

        $time = self::getSignatureTime($parts);

        $oldVerification = null;
        $oldCompare = null;
        if (count($parts) === 3) {
            $oldVerification = self::getOldSignatureVerification($parts);
            $oldCompare = self::sign($oldSecret, $time, $hookUrl, $body);
        }

        $verification = self::getSignatureVerification($parts);
        $compare = self::sign($secret, $time, $hookUrl, $body);

        // It might be that we have not updated the secret jet, but on the other side it was already updated
        return $verification === $compare || $oldVerification === $compare || $verification === $oldCompare || $oldVerification === $oldCompare;
    }

    protected static function sign(string $secret, string $time, string $hookUrl, string $content): string
    {
        $input = sprintf('%s.%s.%s', $time, $hookUrl, $content);
        return hash_hmac(self::DIGEST, $input, $secret);
    }

    protected static function getSignatureTime(array $parts): string
    {
        foreach ($parts as $part) {
            if (str_starts_with($part, 't='))
                return substr($part, 2);
        }

        throw new InvalidArgumentException('Missing time (t=) in signature.');
    }

    protected static function getSignatureVerification(array $parts): string
    {
        foreach ($parts as $part) {
            if (str_starts_with($part, 'v='))
                return substr($part, 2);
        }

        throw new InvalidArgumentException('Missing verification (v=) in signature.');
    }

    protected static function getOldSignatureVerification(array $parts): string
    {
        foreach ($parts as $part) {
            if (str_starts_with($part, 'v0='))
                return substr($part, 3);
        }

        throw new InvalidArgumentException('Missing old verification (v0=) in signature.');
    }
}
