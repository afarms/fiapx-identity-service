package br.com.fiap.fiapx.identity.core.usecase;
import br.com.fiap.fiapx.identity.core.domain.*;
import br.com.fiap.fiapx.identity.core.domain.Account.Role;
import br.com.fiap.fiapx.identity.core.gateway.*;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import static br.com.fiap.fiapx.identity.core.exception.IdentityException.Code.*;
import java.time.Clock;
import java.util.*;
import java.nio.charset.StandardCharsets;
public class IdentityService {
    private final AccountGateway accounts;
    private final PasswordGateway passwords;
    private final TokenGateway tokens;
    private final Clock clock;
    private final String dummyHash;
    public IdentityService(AccountGateway accounts, PasswordGateway passwords, TokenGateway tokens, Clock clock) {
        this.accounts=Objects.requireNonNull(accounts); this.passwords=Objects.requireNonNull(passwords);
        this.tokens=Objects.requireNonNull(tokens); this.clock=Objects.requireNonNull(clock);
        this.dummyHash=passwords.hash(UUID.randomUUID().toString());
    }
    public Account register(String name, String email, String password) {
        String normalized=Account.normalizeEmail(email);
        String validName=Account.validName(name); checkPassword(password);
        String hash=passwords.hash(password);
        return accounts.locked(() -> {
            if (accounts.findByEmail(normalized).isPresent()) throw new IdentityException(CONFLICT);
            return accounts.save(new Account(UUID.randomUUID(),validName,normalized,hash,Role.USER,true,0,clock.instant()));
        });
    }
    public String login(String email, String password) {
        String normalized;
        try { normalized=Account.normalizeEmail(email); } catch (IllegalArgumentException e) { normalized=""; }
        var account=accounts.findByEmail(normalized);
        boolean matched=passwords.matches(password,account.map(Account::passwordHash).orElse(dummyHash));
        if (!matched || account.isEmpty() || !account.get().active()) throw new IdentityException(UNAUTHORIZED);
        return tokens.issue(account.get());
    }
    public Account current(UUID id, long version) {
        var account=accounts.findById(id).orElseThrow(() -> new IdentityException(UNAUTHORIZED));
        if (account.credentialVersion()!=version) throw new IdentityException(UNAUTHORIZED);
        if (!account.active()) throw new IdentityException(FORBIDDEN);
        return account;
    }
    public Account profile(UUID actor, long version, String name) {
        return accounts.locked(() -> accounts.save(current(actor,version).profile(name)));
    }
    public void credentials(UUID actor,long version,String currentPassword,String email,String newPassword) {
        String normalized=Account.normalizeEmail(email); checkPassword(newPassword);
        accounts.locked(() -> {
            var account=current(actor,version);
            if (!passwords.matches(currentPassword,account.passwordHash())) throw new IdentityException(UNAUTHORIZED);
            if (accounts.findByEmail(normalized).filter(a -> !a.id().equals(actor)).isPresent()) throw new IdentityException(CONFLICT);
            accounts.save(account.credentials(normalized,passwords.hash(newPassword))); return null;
        });
    }
    private Account admin(UUID actor,long version) {
        var account=current(actor,version);
        if (account.role()!=Role.ADMIN) throw new IdentityException(FORBIDDEN);
        return account;
    }
    public AccountPage list(UUID actor,long version,int page,int size) {
        admin(actor,version);
        if (page<0 || size<1 || size>100) throw new IllegalArgumentException("Invalid pagination");
        return accounts.list(page,size);
    }
    public Account permissions(UUID actor,long version,UUID target,Role role,boolean active) {
        Objects.requireNonNull(role);
        return accounts.locked(() -> {
            admin(actor,version);
            var account=accounts.findById(target).orElseThrow(() -> new IdentityException(NOT_FOUND));
            if (account.active() && account.role()==Role.ADMIN && (!active || role!=Role.ADMIN)
                    && accounts.countActiveAdmins()<=1) throw new IdentityException(CONFLICT);
            return accounts.save(account.permissions(role,active));
        });
    }
    public void bootstrap(String name,String email,String password) {
        String normalized=Account.normalizeEmail(email); String validName=Account.validName(name); checkPassword(password);
        accounts.locked(() -> {
            var existing=accounts.findByEmail(normalized);
            if (existing.isPresent()) {
                if (existing.get().role()!=Role.ADMIN || !existing.get().active()) throw new IdentityException(CONFLICT);
                return null;
            }
            if (accounts.countActiveAdmins()>0) return null;
            accounts.save(new Account(UUID.randomUUID(),validName,normalized,passwords.hash(password),Role.ADMIN,true,0,clock.instant()));
            return null;
        });
    }
    public static void checkPassword(String password) {
        if (password==null || password.codePointCount(0,password.length())<12
                || password.getBytes(StandardCharsets.UTF_8).length>72) throw new IllegalArgumentException("Password must contain at least 12 characters and at most 72 UTF-8 bytes");
    }
}
