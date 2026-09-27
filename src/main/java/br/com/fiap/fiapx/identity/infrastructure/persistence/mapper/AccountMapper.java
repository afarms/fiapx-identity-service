package br.com.fiap.fiapx.identity.infrastructure.persistence.mapper;
import br.com.fiap.fiapx.identity.core.domain.Account;
import br.com.fiap.fiapx.identity.infrastructure.persistence.entity.AccountEntity;
public class AccountMapper {
    public AccountEntity toEntity(Account a) {
        var e=new AccountEntity(); e.id=a.id(); e.name=a.name(); e.email=a.email(); e.passwordHash=a.passwordHash();
        e.role=a.role().name(); e.active=a.active(); e.credentialVersion=a.credentialVersion(); e.createdAt=a.createdAt(); return e;
    }
    public Account toDomain(AccountEntity e) {
        return new Account(e.id,e.name,e.email,e.passwordHash,Account.Role.valueOf(e.role),e.active,e.credentialVersion,e.createdAt);
    }
}
