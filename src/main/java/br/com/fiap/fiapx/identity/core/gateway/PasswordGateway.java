package br.com.fiap.fiapx.identity.core.gateway;
public interface PasswordGateway {
    String hash(String raw);
    boolean matches(String raw, String hash);
}
