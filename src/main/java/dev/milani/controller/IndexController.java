package dev.milani.controller;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import dev.milani.model.LoginForm;
import dev.milani.service.JwtService;
import dev.milani.service.KeycloakRestService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static dev.milani.config.SwaggerConfig.BEARER_KEY_SECURITY_SCHEME;

@RestController
@RequestMapping("api")
public class IndexController {

    private final Logger logger = LoggerFactory.getLogger(IndexController.class);

    private final KeycloakRestService keycloakRestService;
    private final JwtService jwtService;

    public IndexController(KeycloakRestService keycloakRestService, JwtService jwtService) {
        this.keycloakRestService = keycloakRestService;
        this.jwtService = jwtService;
    }

    @Operation(security = {@SecurityRequirement(name = BEARER_KEY_SECURITY_SCHEME)})
    @GetMapping("check-role")
    public Map<String, String> checkRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Schema(allowableValues = {"USER", "ADMIN"}) String role) {
        try {
            DecodedJWT jwt = JWT.decode(authHeader.replace("Bearer", "").trim());

            // check JWT is valid
            Jwk jwk = jwtService.getJwk(jwt);
            final PublicKey publicKey = jwk.getPublicKey();
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Key with ID " + jwt.getKeyId() + " was found in JWKS but is not a RSA-key.");
            }

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
            algorithm.verify(jwt);

            // check JWT role is correct
            Collection<String> roles = jwtService.getRoles(jwt);
            if (!roles.contains(role))
                throw new Exception("not a " + role + " role");

            // check JWT is still active
            Date expiryDate = jwt.getExpiresAt();
            if (expiryDate.before(new Date()))
                throw new Exception("token is expired");

            // all validation passed
            return new HashMap<>() {{
                put("role", String.join(", ", roles));
            }};
        } catch (Exception e) {
            logger.error("exception : {} ", e.getMessage());
            return new HashMap<>() {{
                put("status", "forbidden");
            }};
        }
    }

    @Operation(security = {@SecurityRequirement(name = BEARER_KEY_SECURITY_SCHEME)})
    @GetMapping("valid")
    public Map<String, String> valid(@Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        try {
            String userInfo = keycloakRestService.checkValidity(authHeader);
            return new HashMap<>() {{
                put("is_valid", "true");
                put("userinfo", userInfo);
            }};
        } catch (Exception e) {
            logger.error("token is not valid, exception : {} ", e.getMessage());
            return new HashMap<>() {{
                put("is_valid", "false");
            }};
        }
    }

    @PostMapping(value = "login-rest", produces = MediaType.APPLICATION_JSON_VALUE)
    public String login(@RequestBody LoginForm form) {
        return keycloakRestService.login(form.username(), form.password());
    }

    @GetMapping(value = "login", produces = MediaType.APPLICATION_JSON_VALUE)
    public String login(String code) {
        try {
            return keycloakRestService.login(code);
        } catch (Exception e) {
            logger.error("code is not valid, exception : {} ", e.getMessage());
            return e.getMessage();
        }
    }

    @PostMapping(value = "refresh", produces = MediaType.APPLICATION_JSON_VALUE)
    public String refresh(@RequestParam(value = "refresh_token", name = "refresh_token") String refreshToken) {
        try {
            return keycloakRestService.refresh(refreshToken);
        } catch (Exception e) {
            logger.error("unable to refresh token, exception : {} ", e.getMessage());
            return e.getMessage();
        }
    }

    @PostMapping(value = "logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> logout(@RequestParam(value = "refresh_token", name = "refresh_token") String refreshToken) {
        try {
            keycloakRestService.logout(refreshToken);
            return new HashMap<>() {{
                put("logout", "true");
            }};
        } catch (Exception e) {
            logger.error("unable to logout, exception : {} ", e.getMessage());
            return new HashMap<>() {{
                put("logout", "false");
            }};
        }
    }

    @GetMapping("status")
    public Map<String, String> index() throws UnknownHostException {
        return new HashMap<>() {{
            put("status", "ok");
            put("hostAddress", InetAddress.getLocalHost().getHostAddress());
            put("hostName", InetAddress.getLocalHost().getHostName());
        }};
    }
}
