package dev.milani.model;

import io.swagger.v3.oas.annotations.media.Schema;

public record LoginForm(
        @Schema(defaultValue = "user") String username,
        @Schema(defaultValue = "user") String password
) {
}
