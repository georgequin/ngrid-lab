package ng.ccisonfi.nibbslab.controller;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import ng.ccisonfi.nibbslab.service.LedgerService;

/**
 * Customer-facing transfer + account endpoints.
 *
 * <p><b>Intentionally vulnerable.</b> Planted issues:</p>
 * <ul>
 *   <li><b>BOLA / IDOR</b> — {@code GET /api/accounts/{id}} returns any
 *       account without checking that it belongs to the caller's subject.</li>
 *   <li><b>SQL injection</b> — forwards raw input to {@link LedgerService}.</li>
 *   <li><b>Missing authorization & no balance check</b> on transfers; a caller
 *       can move money out of an account that is not theirs, even overdrawn.</li>
 *   <li><b>Mass-assignment-ish</b> — {@code from} comes from the request body,
 *       never from the authenticated subject.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class TransferController {

    private final LedgerService ledger;

    public TransferController(LedgerService ledger) {
        this.ledger = ledger;
    }

    // IDOR: no check that {id} is owned by req attribute "lab.subject".
    @GetMapping("/accounts/{id}")
    public List<Map<String, Object>> account(@PathVariable String id) {
        return ledger.findAccount(id);
    }

    // SQLi: owner query param flows straight into a LIKE clause.
    @GetMapping("/accounts")
    public List<Map<String, Object>> search(@RequestParam String owner) {
        return ledger.findAccountsByOwner(owner);
    }

    @GetMapping("/accounts/{id}/transfers")
    public List<Map<String, Object>> transfers(@PathVariable String id) {
        return ledger.recentTransfers(id);
    }

    /**
     * Transfer money. The "from" account is taken from the body, and there is
     * no authorization check tying it to the caller, no balance check, and no
     * amount validation (negative amounts "work").
     */
    @PostMapping("/transfers")
    public Map<String, Object> transfer(@RequestBody TransferRequest body,
                                        HttpServletRequest req) {
        // Uses the racy check-then-act path (TOCTOU double-spend exercise).
        long id = ledger.transferWithBalanceCheck(body.from, body.to, body.amountMinor, body.memo);
        if (id < 0) {
            return Map.of("status", "DECLINED", "reason", "insufficient funds (at time of check)");
        }
        return Map.of(
                "transferId", id,
                "status", "POSTED",
                "fromBalanceAfter", ledger.balanceMinor(body.from),
                "actingSubject", String.valueOf(req.getAttribute("lab.subject")));
    }

    /** Simple DTO; all fields caller-controlled. */
    public static class TransferRequest {
        public long from;
        public long to;
        public long amountMinor;
        public String memo;
    }
}
