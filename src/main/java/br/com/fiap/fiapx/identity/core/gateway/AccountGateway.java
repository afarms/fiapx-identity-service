package br.com.fiap.fiapx.identity.core.gateway;
import br.com.fiap.fiapx.identity.core.domain.*;
import java.util.*;
import java.util.function.Supplier;
public interface AccountGateway {
    Optional<Account> findById(UUID id);
    Optional<Account> findByEmail(String email);
    Account save(Account account);
    long countActiveAdmins();
    AccountPage list(int page, int size);
    <T> T locked(Supplier<T> work);
}
