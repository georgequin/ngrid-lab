package ng.ccisonfi.nibbslab.controller;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Token + key endpoints for the JWT exercises. Deliberately generous:
 * anyone can mint a USER token, fetch the public key, and mint a service
 * (RS256) token — the whole point is to give participants material to attack
 * the {@code VulnerableJwtFilter}.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    @Value("${lab.jwt.hmac-secret:secret}")
    private String hmacSecret;

    private final String publicKeyPem;

    public AuthController(String labPublicKeyPem) {
        this.publicKeyPem = labPublicKeyPem;
    }

    /** "Login": no password check; returns an HS256 token signed with the weak secret. */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody(required = false) Map<String, Object> body) {
        String sub = body != null && body.get("username") != null
                ? String.valueOf(body.get("username")) : "alice";
        String header = B64.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64.encodeToString(
                ("{\"sub\":\"" + sub + "\",\"role\":\"USER\",\"internal\":false}")
                        .getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload;
        String sig = hmacSha256(signingInput, hmacSecret.getBytes(StandardCharsets.UTF_8));
        return Map.of("token", signingInput + "." + sig);
    }

    /** Publishes the RSA public key — needed for the RS256->HS256 confusion attack. */
    @GetMapping(value = "/pubkey", produces = MediaType.TEXT_PLAIN_VALUE)
    public String pubkey() {
        return publicKeyPem;
    }

    /** Issues a legitimate RS256 "service" token signed with the lab private key. */
    @PostMapping("/service-token")
    public Map<String, Object> serviceToken() throws Exception {
        String header = B64.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64.encodeToString(
                "{\"sub\":\"settlement-svc\",\"role\":\"SERVICE\",\"internal\":true}"
                        .getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload;

        PrivateKey pk = loadPrivateKey();
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pk);
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        String sig = B64.encodeToString(signer.sign());
        return Map.of("token", signingInput + "." + sig);
    }

    private static String hmacSha256(String data, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return B64.encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String pem;
        try (var in = new ClassPathResource("keys/lab_rsa_private.pem").getInputStream()) {
            pem = StreamUtils.copyToString(in, StandardCharsets.UTF_8);
        }
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
