package ng.ccisonfi.nibbslab.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ng.ccisonfi.nibbslab.service.LedgerService;

/**
 * Ledger reset hook so a participant can restore wiped/corrupted balances on
 * demand after double-spend or injection exercises. Intentionally unauthenticated
 * (exempted in the JWT filter) — it is a lab convenience, not a real endpoint.
 */
@RestController
@RequestMapping("/reset")
public class ResetController {

    private final LedgerService ledger;

    public ResetController(LedgerService ledger) {
        this.ledger = ledger;
    }

    @PostMapping
    public Map<String, Object> reset() {
        ledger.resetLedger();
        return Map.of("status", "RESET", "accounts", "1001,1002,1003,1004,1005,1006,1007,9001");
    }
}
