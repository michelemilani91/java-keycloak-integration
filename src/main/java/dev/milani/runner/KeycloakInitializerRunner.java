package dev.milani.runner;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.net.UnknownHostException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class KeycloakInitializerRunner implements CommandLineRunner {

    private final Logger logger = LoggerFactory.getLogger(KeycloakInitializerRunner.class);

    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;
    @Value("${keycloak.redirect-url}")
    private String keycloakRedirectUrl;
    @Value("${keycloak.realm-name}")
    private String realmName;
    @Value("${keycloak.client-secret}")
    private String clientSecret;
    private final String clientId;
    private final List<UserPass> DEFAULT_USERS;

    private record UserPass(String username, String password, Map<String, List<String>> roles) {
    }

    private final Keycloak keycloakAdmin;

    public KeycloakInitializerRunner(@Value("${keycloak.client-id}") String clientId, Keycloak keycloakAdmin) {
        this.keycloakAdmin = keycloakAdmin;
        this.clientId = clientId;
        DEFAULT_USERS = Arrays.asList(
                new UserPass("admin", "admin", new HashMap<>() {
                    {
                        put(clientId, Arrays.asList("ADMIN", "USER"));
                    }
                }),
                new UserPass("user", "user", new HashMap<>() {
                    {
                        put(clientId, Arrays.asList("USER"));
                    }
                }));
    }

    @Override
    public void run(String... args) {
        logger.info("Initializing '{}' realm in Keycloak ...", realmName);

        Optional<RealmRepresentation> representationOptional = keycloakAdmin.realms()
                .findAll()
                .stream()
                .filter(r -> r.getRealm().equals(realmName))
                .findAny();
        if (representationOptional.isPresent()) {
            logger.info("Removing already pre-configured '{}' realm", realmName);
            keycloakAdmin.realm(realmName).remove();
        }

        // Realm
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(realmName);
        realmRepresentation.setEnabled(true);
        realmRepresentation.setRegistrationAllowed(true);
        // realmRepresentation.setCertificate();

        // Client
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        // the default authentication type is openid-connect, we don't need to set it
        clientRepresentation.setClientId(clientId);
        clientRepresentation.setDirectAccessGrantsEnabled(true);
        clientRepresentation.setPublicClient(true);
        clientRepresentation.setRedirectUris(Arrays.asList(keycloakRedirectUrl));
        clientRepresentation.setSecret(clientSecret); // usually generated, but for this example we configure ours to simplify
        realmRepresentation.setClients(Collections.singletonList(clientRepresentation));

        // Users
        List<UserRepresentation> userRepresentations = DEFAULT_USERS.stream()
                .map(userPass -> {
                    // User Credentials
                    CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
                    credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
                    credentialRepresentation.setValue(userPass.password());

                    // User
                    UserRepresentation userRepresentation = new UserRepresentation();
                    userRepresentation.setUsername(userPass.username());
                    userRepresentation.setEnabled(true);
                    userRepresentation.setCredentials(Collections.singletonList(credentialRepresentation));
                    userRepresentation.setClientRoles(userPass.roles());
                    userRepresentation.setCreatedTimestamp(Instant.now().toEpochMilli());

                    return userRepresentation;
                })
                .collect(Collectors.toList());
        realmRepresentation.setUsers(userRepresentations);

        // Create Realm
        keycloakAdmin.realms().create(realmRepresentation);

        // Testing
        UserPass admin = DEFAULT_USERS.get(0);
        logger.info("Testing getting token for '{}' ...", admin.username());

        try (Keycloak keycloak = KeycloakBuilder.builder().serverUrl(keycloakServerUrl)
                .realm(realmName).username(admin.username()).password(admin.password())
                .clientId(clientId).build()) {

            logger.info("'{}' token: {}", admin.username(), keycloak.tokenManager().grantToken().getToken());
        }
        logger.info("'{}' initialization completed successfully!", realmName);
    }

}