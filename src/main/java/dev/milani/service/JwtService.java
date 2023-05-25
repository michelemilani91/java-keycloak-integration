package dev.milani.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.List;
import java.util.Map;

@Service
public class JwtService {

    @Value("${keycloak.jwk-set-uri}")
    private String jwksUrl;
    @Value("${keycloak.client-id}")
    private String clientId;

    @Cacheable(value = "jwkCache")
    public Jwk getJwk(DecodedJWT jwt) throws Exception {
        return new UrlJwkProvider(new URL(jwksUrl)).get(jwt.getKeyId());
    }

    public List<String> getRoles(DecodedJWT jwt) {
        Map<String, List<String>> map = (Map) jwt.getClaim("resource_access").asMap().get(clientId);
        return map.get("roles");
    }
}
