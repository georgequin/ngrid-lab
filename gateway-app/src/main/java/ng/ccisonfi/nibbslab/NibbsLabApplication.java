package ng.ccisonfi.nibbslab;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

import ng.ccisonfi.nibbslab.security.VulnerableJwtFilter;

/**
 * Entry point for the intentionally vulnerable nibbs-api-lab gateway.
 *
 * <p>This application exists only to practice finding and fixing web/API
 * security bugs in a local, isolated environment. It is insecure on purpose.
 * Do not run it on a reachable network and do not reuse any of this code.</p>
 */
@SpringBootApplication
public class NibbsLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(NibbsLabApplication.class, args);
    }

    /** Weak, crackable HS256 secret (overridable via LAB_JWT_SECRET). */
    @Value("${lab.jwt.hmac-secret:secret}")
    private String hmacSecret;

    /** Exact PEM text of the lab's RSA public key, loaded from the classpath. */
    @Bean
    public String labPublicKeyPem() throws Exception {
        try (var in = new ClassPathResource("keys/lab_rsa_public.pem").getInputStream()) {
            return StreamUtils.copyToString(in, StandardCharsets.UTF_8);
        }
    }

    @Bean
    public FilterRegistrationBean<VulnerableJwtFilter> jwtFilter(String labPublicKeyPem) {
        FilterRegistrationBean<VulnerableJwtFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new VulnerableJwtFilter(hmacSecret, labPublicKeyPem));
        reg.addUrlPatterns("/api/*", "/internal/*");
        reg.setOrder(1);
        return reg;
    }
}
