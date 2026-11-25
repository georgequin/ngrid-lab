package ng.ccisonfi.nibbslab.controller;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import ng.ccisonfi.nibbslab.service.LedgerService;

/**
 * "Internal" settlement surface — meant to be reachable only from within the
 * trust boundary.
 *
 * <p><b>Intentionally vulnerable.</b> Planted issues:</p>
 * <ul>
 *   <li><b>Broken network segmentation</b> — the edge proxy's {@code /internal}
 *       deny rule is bypassable (case, {@code //internal}, encoded dot), so this
 *       surface is reachable from outside.</li>
 *   <li><b>Trusts the spoofable {@code X-Internal-Caller} header</b> (via the
 *       JWT filter) for its "admin" authorization.</li>
 *   <li><b>Privileged, unvalidated money movement</b> — bulk settlement with no
 *       authorization tying the caller to the accounts and no limits.</li>
 * </ul>
 */
@RestController
@RequestMapping("/internal")
public class InternalSettlementController {

    private final LedgerService ledger;

    public InternalSettlementController(LedgerService ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/settlement/health")
    public Map<String, Object> health(HttpServletRequest req) {
        return Map.of(
                "ok", true,
                "internal", req.getAttribute("lab.internal"),
                "role", req.getAttribute("lab.role"));
    }

    /**
     * Posts a batch of settlement legs. Only checks the (spoofable) role
     * attribute, which the JWT filter will happily set to ADMIN from a
     * client header or an unsigned token.
     */
    @PostMapping("/settlement/batch")
    public Map<String, Object> batch(@RequestBody List<Leg> legs,
                                     HttpServletRequest req) {
        Object role = req.getAttribute("lab.role");
        if (!"ADMIN".equals(role)) {
            return Map.of("status", "DENIED", "reason", "admin role required");
        }

        long posted = 0;
        for (Leg leg : legs) {
            ledger.transferWithBalanceCheck(leg.from, leg.to, leg.amountMinor, "settlement:" + leg.ref);
            posted++;
        }
        return Map.of("status", "SETTLED", "legsPosted", posted);
    }

    public static class Leg {
        public long from;
        public long to;
        public long amountMinor;
        public String ref;
    }
}
