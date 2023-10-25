package io.fliqa.example;

import java.io.*;
import java.nio.charset.*;
import java.util.*;

public class TestHelper {

    private TestHelper() { // hide constructor
        throw new IllegalStateException("Utility class!");
    }

    public static String removeWhitespace(String input) {
        return input == null ? null : input.trim().replaceAll("\\s", "");
    }

    public static String readResourceToString(String resourceFile) {

        Objects.requireNonNull(resourceFile, String.format("Missing resource file: %s", resourceFile));
        Scanner scanner = null;

        try {
            InputStream resource = TestHelper.class.getResourceAsStream(resourceFile);
            Objects.requireNonNull(resource, String.format("Can't load resource file: %s", resourceFile));
            scanner = new Scanner(resource, StandardCharsets.UTF_8);
            return scanner.useDelimiter("\\A").next();
        } catch (Exception e) {
            return null;
        } finally {
            if (scanner != null) {
                scanner.close();
            }
        }
    }
}
