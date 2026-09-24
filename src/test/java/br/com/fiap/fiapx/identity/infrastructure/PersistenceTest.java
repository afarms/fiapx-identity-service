package br.com.fiap.fiapx.identity.infrastructure;
import br.com.fiap.fiapx.identity.core.domain.*;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import br.com.fiap.fiapx.identity.infrastructure.persistence.adapter.*;
import br.com.fiap.fiapx.identity.infrastructure.persistence.mapper.*;
import br.com.fiap.fiapx.identity.infrastructure.persistence.entity.*;
import br.com.fiap.fiapx.identity.infrastructure.persistence.repository.*;
import org.springframework.transaction.support.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.*;
import org.springframework.data.domain.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.time.Instant;
class PersistenceTest {
    @Test void mapsPersistsQueriesListsCountsAndLocks() {
        var repository=mock(SpringAccountRepository.class); var mapper=new AccountMapper();
        var jdbc=mock(JdbcTemplate.class); var tx=mock(TransactionTemplate.class);
        when(tx.execute(any())).thenAnswer(i -> ((TransactionCallback<?>)i.getArgument(0)).doInTransaction(mock(org.springframework.transaction.TransactionStatus.class)));
        var adapter=new AccountGatewayAdapter(repository,mapper,jdbc,tx);
        var account=new Account(UUID.randomUUID(),"Name","name@example.com","encoded",Account.Role.ADMIN,true,5,Instant.now());
        var entity=mapper.toEntity(account);
        assertEquals(account,mapper.toDomain(entity));
        when(repository.findById(account.id())).thenReturn(Optional.of(entity));
        when(repository.findByEmail(account.email())).thenReturn(Optional.of(entity));
        when(repository.saveAndFlush(any())).thenAnswer(i -> i.getArgument(0));
        when(repository.countByRoleAndActiveTrue("ADMIN")).thenReturn(1L);
        when(repository.findAll(PageRequest.of(0,20,Sort.by("createdAt","id"))))
            .thenReturn(new PageImpl<>(List.of(entity),PageRequest.of(0,20),1));
        assertEquals(account,adapter.save(account)); assertEquals(account,adapter.findById(account.id()).orElseThrow());
        assertEquals(account,adapter.findByEmail(account.email()).orElseThrow()); assertEquals(1,adapter.countActiveAdmins());
        assertEquals(List.of(account),adapter.list(0,20).items());
        assertEquals(account,adapter.locked(() -> adapter.findById(account.id()).orElseThrow()));
        verify(jdbc).execute("SELECT pg_advisory_xact_lock(170024001)");
        var missing=UUID.randomUUID(); assertTrue(adapter.findById(missing).isEmpty());
        when(repository.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("sensitive"));
        assertEquals(IdentityException.Code.CONFLICT,assertThrows(IdentityException.class,() -> adapter.save(account)).code());
        when(repository.findById(any())).thenThrow(new DataAccessResourceFailureException("sensitive"));
        assertEquals(IdentityException.Code.UNAVAILABLE,assertThrows(IdentityException.class,() -> adapter.findById(missing)).code());
    }
}
