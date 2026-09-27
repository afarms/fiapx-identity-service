package br.com.fiap.fiapx.identity.infrastructure.security;
import br.com.fiap.fiapx.identity.core.gateway.PasswordGateway;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.nio.charset.StandardCharsets;
public class PasswordAdapter implements PasswordGateway {
    private final PasswordEncoder encoder;
    public PasswordAdapter(PasswordEncoder encoder) { this.encoder=encoder; }
    public String hash(String raw) { return encoder.encode(raw); }
    public boolean matches(String raw,String hash) {
        if (raw==null || raw.getBytes(StandardCharsets.UTF_8).length>72) return false;
        return encoder.matches(raw,hash);
    }
}
