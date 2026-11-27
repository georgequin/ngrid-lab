package ng.ccisonfi.nibbslab.service;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Ledger access layer.
 *
 * <p><b>Intentionally vulnerable.</b> Planted issues:</p>
 * <ul>
 *   <li><b>SQL injection</b> — read queries are built with string
 *       concatenation; the {@code api_keys} table is a UNION target.</li>
 *   <li><b>TOCTOU double-spend</b> — {@link #transferWithBalanceCheck} reads the
 *       balance, sleeps, then debits, with no row lock and no serializable
 *       isolation, so concurrent requests all pass the same check.</li>
 * </ul>
 * Do not copy these patterns; real code uses parameterized queries and either
 * {@code SELECT ... FOR UPDATE} or a conditional {@code UPDATE ... WHERE balance >= ?}.
 */
@Service
public class LedgerService {

    private final JdbcTemplate jdbc;

    public LedgerService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ---------------------------------------------------------------------
    // SQL-injection surface (string concatenation, on purpose)
    // ---------------------------------------------------------------------

    public List<Map<String, Object>> findAccount(String accountId) {
        String sql = "SELECT id, owner_sub, currency, balance_minor "
                + "FROM accounts WHERE id = " + accountId;
        return jdbc.queryForList(sql);
    }

    public List<Map<String, Object>> findAccountsByOwner(String owner) {
        String sql = "SELECT id, owner_sub, currency, balance_minor "
                + "FROM accounts WHERE owner_sub LIKE '%" + owner + "%'";
        return jdbc.queryForList(sql);
    }

    public List<Map<String, Object>> recentTransfers(String accountId) {
        String sql = "SELECT id, from_account, to_account, amount_minor, memo, created_at "
                + "FROM transfers WHERE from_account = " + accountId
                + " OR to_account = " + accountId
                + " ORDER BY created_at DESC LIMIT 50";
        return jdbc.queryForList(sql);
    }

    // ---------------------------------------------------------------------
    // TOCTOU double-spend surface
    // ---------------------------------------------------------------------

    public long balanceMinor(long accountId) {
        Long bal = jdbc.queryForObject(
                "SELECT balance_minor FROM accounts WHERE id = ?", Long.class, accountId);
        return bal == null ? 0L : bal;
    }

    /**
     * Check-then-act transfer with a deliberate window between the balance read
     * and the debit. No {@code FOR UPDATE}, no serializable transaction — fire
     * N concurrent requests for an amount &gt; (balance / N) and they all pass.
     *
     * @return the new transfer id, or -1 if the (racy) balance check "failed".
     */
    public long transferWithBalanceCheck(long fromAccount, long toAccount,
                                         long amountMinor, String memo) {
        // TIME-OF-CHECK
        long balance = balanceMinor(fromAccount);
        if (balance < amountMinor) {
            return -1L;
        }

        // The race window the exercise exploits.
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // TIME-OF-USE (no re-check, no lock)
        jdbc.update("UPDATE accounts SET balance_minor = balance_minor - ? WHERE id = ?",
                amountMinor, fromAccount);
        jdbc.update("UPDATE accounts SET balance_minor = balance_minor + ? WHERE id = ?",
                amountMinor, toAccount);
        return jdbc.queryForObject(
                "INSERT INTO transfers (from_account, to_account, amount_minor, memo) "
                        + "VALUES (?, ?, ?, ?) RETURNING id",
                Long.class, fromAccount, toAccount, amountMinor, memo);
    }

    // ---------------------------------------------------------------------
    // Reset hook
    // ---------------------------------------------------------------------

    /** Wipes transfers and restores seed balances so a seat can be re-run. */
    public void resetLedger() {
        jdbc.update("DELETE FROM transfers");
        jdbc.update("UPDATE accounts SET balance_minor = 2500000 WHERE id = 1001");
        jdbc.update("UPDATE accounts SET balance_minor = 180000  WHERE id = 1002");
        jdbc.update("UPDATE accounts SET balance_minor = 90000   WHERE id = 1003");
        jdbc.update("UPDATE accounts SET balance_minor = 1250000 WHERE id = 1004");
        jdbc.update("UPDATE accounts SET balance_minor = 640000  WHERE id = 1005");
        jdbc.update("UPDATE accounts SET balance_minor = 45000   WHERE id = 1006");
        jdbc.update("UPDATE accounts SET balance_minor = 120000  WHERE id = 1007");
        jdbc.update("UPDATE accounts SET balance_minor = 999999999 WHERE id = 9001");
    }
}
