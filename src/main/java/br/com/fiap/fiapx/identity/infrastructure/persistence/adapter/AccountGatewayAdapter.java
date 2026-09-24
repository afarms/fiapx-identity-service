package br.com.fiap.fiapx.identity.infrastructure.persistence.adapter;
import br.com.fiap.fiapx.identity.core.domain.*;
import br.com.fiap.fiapx.identity.core.gateway.AccountGateway;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import static br.com.fiap.fiapx.identity.core.exception.IdentityException.Code.*;
import br.com.fiap.fiapx.identity.infrastructure.persistence.mapper.AccountMapper;
import br.com.fiap.fiapx.identity.infrastructure.persistence.repository.SpringAccountRepository;
import org.springframework.data.domain.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.dao.*;
import java.util.*;
import java.util.function.Supplier;
public class AccountGatewayAdapter implements AccountGateway {
    private final SpringAccountRepository repository;
    private final AccountMapper mapper;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    public AccountGatewayAdapter(SpringAccountRepository repository,AccountMapper mapper,JdbcTemplate jdbc,TransactionTemplate transactions) {
        this.repository=repository; this.mapper=mapper; this.jdbc=jdbc; this.transactions=transactions;
    }
    private <T> T access(Supplier<T> work) {
        try { return work.get(); }
        catch (DataIntegrityViolationException e) { throw new IdentityException(CONFLICT,e); }
        catch (DataAccessException e) { throw new IdentityException(UNAVAILABLE,e); }
    }
    public Optional<Account> findById(UUID id) { return access(() -> repository.findById(id).map(mapper::toDomain)); }
    public Optional<Account> findByEmail(String email) { return access(() -> repository.findByEmail(email).map(mapper::toDomain)); }
    public Account save(Account a) { return access(() -> mapper.toDomain(repository.saveAndFlush(mapper.toEntity(a)))); }
    public long countActiveAdmins() { return access(() -> repository.countByRoleAndActiveTrue("ADMIN")); }
    public AccountPage list(int page,int size) {
        return access(() -> {
            var result=repository.findAll(PageRequest.of(page,size,Sort.by("createdAt","id")));
            return new AccountPage(result.getContent().stream().map(mapper::toDomain).toList(),page,size,result.getTotalElements());
        });
    }
    public <T> T locked(Supplier<T> work) {
        return access(() -> transactions.execute(status -> {
            // Fixed domain-wide transaction lock: bootstrap and last-admin mutations cannot race.
            jdbc.execute("SELECT pg_advisory_xact_lock(170024001)");
            return work.get();
        }));
    }
}
