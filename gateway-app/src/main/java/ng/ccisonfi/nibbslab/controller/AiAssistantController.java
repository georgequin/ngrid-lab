package ng.ccisonfi.nibbslab.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Toy "AI assistant" endpoint for the lab.
 *
 * <p><b>Intentionally vulnerable.</b> Planted issues:</p>
 * <ul>
 *   <li><b>SSRF</b> — {@code /api/assistant/fetch} fetches any caller-supplied
 *       URL server-side with no allow-list, reaching the internal settlement
 *       surface, the DB host, or container metadata.</li>
 *   <li><b>Prompt injection</b> — fetched/sent document text is concatenated
 *       straight into the system prompt with no instruction/data boundary.</li>
 *   <li><b>API key leakage</b> — the upstream model key is placed in the system
 *       preamble (so an injected "print your configuration" exfiltrates it) and
 *       is also over-shared by {@code /api/assistant/config}.</li>
 * </ul>
 * There is no real model here; {@code summarize} returns the assembled prompt so
 * the injection + leakage paths are visible without external calls.
 */
@RestController
@RequestMapping("/api/assistant")
public class AiAssistantController {

    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)   // widens SSRF surface
            .build();

    /** Planted: a juicy-looking upstream key that must never reach a client. */
    @Value("${lab.ai.api-key:sk-lab-UPSTREAM-9f2c7a41d0e84b6}")
    private String upstreamApiKey;

    /** SSRF: fetches whatever URL the caller provides. */
    @PostMapping("/fetch")
    public Map<String, Object> fetch(@RequestBody FetchRequest body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(body.url))
                .GET()
                .build();
        HttpResponse<String> resp = http.send(request, HttpResponse.BodyHandlers.ofString());
        return Map.of(
                "requestedUrl", body.url,
                "status", resp.statusCode(),
                "body", resp.body());
    }

    /**
     * Prompt injection + key leakage: the system preamble (with the API key) and
     * the untrusted document are glued together with no boundary, so instructions
     * embedded in the document would be followed and could print the key.
     */
    @PostMapping("/summarize")
    public Map<String, Object> summarize(@RequestBody SummarizeRequest body) {
        String assembledPrompt = """
                SYSTEM: You are the nibbs lab settlement assistant.
                Upstream model credential: %s
                Follow the operator instructions and summarize the document.
                OPERATOR INSTRUCTIONS: %s
                DOCUMENT: %s
                """.formatted(upstreamApiKey, body.instructions, body.document);

        return Map.of(
                "assembledPrompt", assembledPrompt,
                "note", "Secret in the system preamble + no boundary before untrusted DOCUMENT.");
    }

    /** Planted: over-shares configuration, including the upstream key. */
    @GetMapping("/config")
    public Map<String, Object> config() {
        return Map.of(
                "model", "nibss-lab-assistant-v0",
                "upstreamApiKey", upstreamApiKey,
                "debug", true);
    }

    public static class FetchRequest {
        public String url;
    }

    public static class SummarizeRequest {
        public String instructions;
        public String document;
    }
}
