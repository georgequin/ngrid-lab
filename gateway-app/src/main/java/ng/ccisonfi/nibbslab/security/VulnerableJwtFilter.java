package ng.ccisonfi.nibbslab.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Hand-rolled JWT "verification" filter.
 *
 * <p><b>This class is intentionally vulnerable.</b> It is the centerpiece of
 * the lab's authentication exercises. The planted JWT mistakes are:</p>
 * <ul>
 *   <li><b>alg=none accepted</b> — a token with {@code "alg":"none"} and no
 *       signature is treated as valid (CVE-2015-9235 class).</li>
 *   <li><b>Weak HMAC secret</b> — HS256 tokens are verified against
 *       {@code lab.jwt.hmac-secret} ({@code "secret"} by default), which is in
 *       every wordlist, so it is crackable offline (jwt_tool / hashcat -m 16500)
 *       and forgeable afterward.</li>
 *   <li><b>RS256 → HS256 algorithm confusion</b> — the server publishes an RSA
 *       public key and verifies RS256 service tokens with it, but the HS256
 *       branch <i>also</i> accepts a signature computed with that public key's
 *       PEM bytes as the HMAC secret. An attacker who has the (public) key can
 *       forge an HS256 admin token.</li>
 *   <li><b>No exp / nbf / iss / aud validation.</b></li>
 *   <li><b>Trusts a spoofable header</b> — {@code X-Internal-Caller: true}
 *       bypasses the token requirement entirely.</li>
 * </ul>
 *
 * Do not use any of this outside the lab.
 */
public class VulnerableJwtFilter implements Filter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static final String ATTR_SUBJECT = "lab.subject";
    public static final String ATTR_ROLE = "lab.role";
    public static final String ATTR_INTERNAL = "lab.internal";
    public static final String ATTR_ALG = "lab.alg";

    private final String hmacSecret;
    /** Exact PEM text of the public key, used (wrongly) as an HMAC key too. */
    private final String publicKeyPem;
    private final PublicKey rsaPublicKey;

    public VulnerableJwtFilter(String hmacSecret, String publicKeyPem) {
        this.hmacSecret = hmacSecret;
        this.publicKeyPem = publicKeyPem;
        this.rsaPublicKey = parseRsaPublicKey(publicKeyPem);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Endpoints that must be reachable without a token (issue tokens, reset,
        // publish the public key). Kept deliberately broad for the lab.
        String path = req.getRequestURI();
        if (path.startsWith("/api/auth") || path.startsWith("/reset")
                || path.startsWith("/actuator")) {
            chain.doFilter(request, response);
            return;
        }

        // ---- Planted bypass #1: trust a client-supplied "internal" marker ----
        String internalCaller = req.getHeader("X-Internal-Caller");
        if ("true".equalsIgnoreCase(internalCaller)) {
            req.setAttribute(ATTR_SUBJECT, "internal-system");
            req.setAttribute(ATTR_ROLE, "ADMIN");
            req.setAttribute(ATTR_INTERNAL, Boolean.TRUE);
            chain.doFilter(request, response);
            return;
        }

        String auth = req.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            unauthorized(res, "missing bearer token");
            return;
        }

        String token = auth.substring("Bearer ".length()).trim();
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            unauthorized(res, "malformed token");
            return;
        }

        try {
            JsonNode header = decodeSegment(parts[0]);
            JsonNode payload = decodeSegment(parts[1]);
            String alg = header.path("alg").asText("none");
            String signingInput = parts[0] + "." + parts[1];
            String signature = parts.length >= 3 ? parts[2] : "";

            boolean ok;
            if ("none".equalsIgnoreCase(alg)) {
                ok = true;                                   // bypass #2: alg=none
            } else if ("HS256".equalsIgnoreCase(alg)) {
                ok = verifyHs256(signingInput, signature);   // weak secret OR key confusion
            } else if ("RS256".equalsIgnoreCase(alg)) {
                ok = verifyRs256(signingInput, signature);
            } else {
                unauthorized(res, "unsupported alg: " + alg);
                return;
            }

            if (!ok) {
                unauthorized(res, "signature verification failed");
                return;
            }

            req.setAttribute(ATTR_ALG, alg);
            req.setAttribute(ATTR_SUBJECT, payload.path("sub").asText("anonymous"));
            req.setAttribute(ATTR_ROLE, payload.path("role").asText("USER"));
            req.setAttribute(ATTR_INTERNAL, payload.path("internal").asBoolean(false));
            chain.doFilter(request, response);

        } catch (Exception e) {
            // Planted: leaks parsing details back to the caller.
            unauthorized(res, "token error: " + e.getMessage());
        }
    }

    /**
     * HS256 verification with TWO accepted keys — the planted flaws:
     *   (a) the weak shared secret  -> brute-forceable,
     *   (b) the RSA public key PEM  -> RS256->HS256 confusion forgery.
     */
    private boolean verifyHs256(String signingInput, String signatureB64) throws Exception {
        byte[] provided = Base64.getUrlDecoder().decode(pad(signatureB64));
        for (byte[] key : new byte[][]{
                hmacSecret.getBytes(StandardCharsets.UTF_8),
                publicKeyPem.getBytes(StandardCharsets.UTF_8)}) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] expected = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            if (constantTimeEquals(expected, provided)) {
                return true;
            }
        }
        return false;
    }

    private boolean verifyRs256(String signingInput, String signatureB64) throws Exception {
        if (rsaPublicKey == null) {
            return false;
        }
        byte[] sig = Base64.getUrlDecoder().decode(pad(signatureB64));
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaPublicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(sig);
    }

    private static PublicKey parseRsaPublicKey(String pem) {
        try {
            String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(body);
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            return null;
        }
    }

    private void unauthorized(HttpServletResponse res, String msg) throws IOException {
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.getWriter().write(msg);
    }

    private JsonNode decodeSegment(String segment) throws IOException {
        byte[] decoded = Base64.getUrlDecoder().decode(pad(segment));
        return MAPPER.readTree(new String(decoded, StandardCharsets.UTF_8));
    }

    private static String pad(String s) {
        int mod = s.length() % 4;
        if (mod == 0) return s;
        return s + "====".substring(mod);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= a[i] ^ b[i];
        return r == 0;
    }
}
