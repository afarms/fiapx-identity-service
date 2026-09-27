package br.com.fiap.fiapx.identity.infrastructure.security;
import br.com.fiap.fiapx.identity.core.domain.Account;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import static br.com.fiap.fiapx.identity.core.exception.IdentityException.Code.UNAUTHORIZED;
import static br.com.fiap.fiapx.identity.core.exception.IdentityException.Code.SERVICE_UNAUTHORIZED;
import org.springframework.security.oauth2.jwt.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
public class TokenAccess {
    private final IdentityService service; private final JwtDecoder decoder; private final byte[] serviceKey;
    public TokenAccess(IdentityService service,JwtDecoder decoder,String serviceKey) {
        if(serviceKey==null || serviceKey.length()<32) throw new IllegalArgumentException("Service key must have at least 32 characters");
        this.service=service; this.decoder=decoder; this.serviceKey=serviceKey.getBytes(StandardCharsets.UTF_8);
    }
    public Account current(Jwt jwt) {
        try {
            return service.current(UUID.fromString(jwt.getSubject()),((Number)jwt.getClaim("ver")).longValue());
        } catch (IllegalArgumentException | NullPointerException | ClassCastException e) { throw new IdentityException(UNAUTHORIZED); }
    }
    public Account validate(String key,String token) {
        if(key==null || !MessageDigest.isEqual(serviceKey,key.getBytes(StandardCharsets.UTF_8))) throw new IdentityException(SERVICE_UNAUTHORIZED);
        try { return current(decoder.decode(token)); }
        catch (JwtException | IllegalArgumentException e) { throw new IdentityException(UNAUTHORIZED); }
    }
}
