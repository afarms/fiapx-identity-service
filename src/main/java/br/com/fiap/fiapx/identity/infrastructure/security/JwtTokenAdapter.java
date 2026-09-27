package br.com.fiap.fiapx.identity.infrastructure.security;
import br.com.fiap.fiapx.identity.core.domain.Account;
import br.com.fiap.fiapx.identity.core.gateway.TokenGateway;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import java.time.Clock;
import java.util.List;
public class JwtTokenAdapter implements TokenGateway {
    private final JwtEncoder encoder; private final Clock clock; private final String issuer; private final String audience;
    public JwtTokenAdapter(JwtEncoder encoder,Clock clock,String issuer,String audience) {
        this.encoder=encoder; this.clock=clock; this.issuer=issuer; this.audience=audience;
    }
    public String issue(Account account) {
        var now=clock.instant();
        var claims=JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience)).subject(account.id().toString())
            .issuedAt(now).expiresAt(now.plusSeconds(1800)).claim("ver",account.credentialVersion()).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),claims)).getTokenValue();
    }
}
