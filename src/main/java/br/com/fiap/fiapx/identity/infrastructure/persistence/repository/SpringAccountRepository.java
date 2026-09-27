package br.com.fiap.fiapx.identity.infrastructure.persistence.repository;
import br.com.fiap.fiapx.identity.infrastructure.persistence.entity.AccountEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.*;
public interface SpringAccountRepository extends JpaRepository<AccountEntity,UUID> {
    Optional<AccountEntity> findByEmail(String email);
    long countByRoleAndActiveTrue(String role);
}
