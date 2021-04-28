package me.vitormac.mediaserver;

import io.github.cdimascio.dotenv.Dotenv;

import java.util.Objects;

public class EnvUtils {

    private EnvUtils() {
    }

    public static void check(Dotenv env, String name) {
        if (Objects.isNull(env.get(name, null))) {
            throw new IllegalArgumentException(
                    String.format("Environment variable '%s' is required but not set", name)
            );
        }
    }

}
