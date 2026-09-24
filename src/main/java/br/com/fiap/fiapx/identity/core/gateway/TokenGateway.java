package br.com.fiap.fiapx.identity.core.gateway;
import br.com.fiap.fiapx.identity.core.domain.Account;
public interface TokenGateway { String issue(Account account); }
