package io.fliqa.example.webhook;

import io.fliqa.example.*;
import org.junit.jupiter.api.*;

import java.time.*;

import static io.fliqa.example.TestHelper.*;
import static io.fliqa.example.webhook.WebHookUtils.checkSignature;
import static org.junit.jupiter.api.Assertions.*;

class WebHookUtilsTest {

    String response = removeWhitespace(readResourceToString("/payment/payment_response.json"));

    Instant timestamp = Instant.parse("2023-08-03T08:35:24.00Z");

    @Test
    public void checkGeneratedSignature() {
        assertTrue(checkSignature("t=1691051724,v=3b47cc0de87b2324f14a9c415efe5768b80fc7a8125814ecde33f38f8155d72d",
                                  "MySecret",
                                  null,
                                  "https://my.webhook.url/",
                                  response));

        assertTrue(checkSignature("t=1691051724,v=e3e414763628ae9e6c5c85fda429fcdcd6a5cceec60f1714f4ccc9ed3960f203,v0=80b2ee2b802fbbd18b02a284dea67b13158cc1f733580952e372c162e72a966a",
                                  "Secret",
                                  "OldSecret",
                                  "https://my.webhook.url/",
                                  response));

        assertTrue(checkSignature("t=1691051724,v=3b47cc0de87b2324f14a9c415efe5768b80fc7a8125814ecde33f38f8155d72d,v0=80b2ee2b802fbbd18b02a284dea67b13158cc1f733580952e372c162e72a966a",
                                  "Secret",
                                  "OldSecret",
                                  "https://my.webhook.url/",
                                  response));
    }

    @Test
    public void invalidSignature() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> checkSignature("t=toNiCas,v=3b47cc0de87b2324f14a9c415efe5768b80fc7a8125814ecde33f38f8155d72d",
                                                                                                    "MySecret",
                                                                                                    null,
                                                                                                    "https://my.webhook.url/",
                                                                                                    response));

        assertEquals("Signature time (t=<timestamp>) invalid: 't=toNiCas'!", ex.getMessage());
    }

    @Test
    public void invalidSignatureMissingTime() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> checkSignature("v=3b47cc0de87b2324f14a9c415efe5768b80fc7a8125814ecde33f38f8155d72d",
                                                                                                    "MySecret",
                                                                                                    null,
                                                                                                    "https://my.webhook.url/",
                                                                                                    response));
        assertEquals("Invalid signature, expected time and verification but got: 'v=3b47cc0de87b2324f14a9c415efe5768b80fc7a8125814ecde33f38f8155d72d'!", ex.getMessage());
    }
}