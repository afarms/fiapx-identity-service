package br.com.fiap.fiapx.identity.infrastructure;
import br.com.fiap.fiapx.identity.infrastructure.config.BeanConfig;
import br.com.fiap.fiapx.identity.infrastructure.security.*;
import br.com.fiap.fiapx.identity.core.domain.Account;
import br.com.fiap.fiapx.identity.core.gateway.*;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import br.com.fiap.fiapx.identity.infrastructure.persistence.repository.SpringAccountRepository;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import java.security.*;
import java.security.interfaces.*;
import java.time.*;
import java.util.*;
class SecurityTest {
    static KeyPair pair;
    final BeanConfig config=new BeanConfig();
    final Account account=new Account(UUID.randomUUID(),"User","user@example.com","hash",Account.Role.USER,true,3,Instant.now());
    @BeforeAll static void keys() throws Exception { var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); pair=generator.generateKeyPair(); }
    JwtEncoder encoder() { return config.jwtEncoder((RSAPublicKey)pair.getPublic(),(RSAPrivateKey)pair.getPrivate()); }
    JwtDecoder decoder() { return config.jwtDecoder((RSAPublicKey)pair.getPublic(),"issuer","audience"); }
    String token(JwtClaimsSet claims) { return encoder().encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),claims)).getTokenValue(); }
    JwtClaimsSet.Builder claims() {
        return JwtClaimsSet.builder().issuer("issuer").audience(List.of("audience")).subject(account.id().toString())
            .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(1800)).claim("ver",3L);
    }
    @Test void roundtripAndPasswordHashing() {
        var clock=config.clock(); var gateway=config.tokenGateway(encoder(),clock,"issuer","audience");
        var jwt=decoder().decode(gateway.issue(account));
        assertEquals(account.id().toString(),jwt.getSubject()); assertEquals(3L,((Number)jwt.getClaim("ver")).longValue());
        assertEquals(1800,Duration.between(jwt.getIssuedAt(),jwt.getExpiresAt()).getSeconds());
        var passwords=config.passwordGateway(config.passwordEncoder()); var hash=passwords.hash("long-password");
        assertNotEquals("long-password",hash); assertTrue(passwords.matches("long-password",hash));
        assertFalse(passwords.matches("wrong",hash)); assertFalse(passwords.matches(null,hash)); assertFalse(passwords.matches("x".repeat(73),hash));
    }
    @Test void rejectsWrongIssuerAudienceExpiredMissingAndMalformedClaimsAndTampering() {
        var cases=List.of(
            claims().issuer("wrong").build(),claims().audience(List.of("wrong")).build(),
            claims().issuedAt(Instant.now().minusSeconds(3600)).expiresAt(Instant.now().minusSeconds(1800)).build(),
            claims().issuedAt(Instant.now().minusSeconds(1801)).expiresAt(Instant.now().minusSeconds(1)).build(),
            claims().subject("invalid").build(),claims().claim("ver",-1L).build(),claims().claim("ver","3").build(),
            claims().claim("ver",3.5).build(),
            claims().expiresAt(Instant.now().plusSeconds(3600)).build(),
            claims().issuedAt(Instant.now().plusSeconds(90)).expiresAt(Instant.now().plusSeconds(1800)).build(),
            JwtClaimsSet.builder().issuer("issuer").audience(List.of("audience")).subject(account.id().toString()).claim("ver",3).build(),
            JwtClaimsSet.builder().issuer("issuer").audience(List.of("audience")).subject(account.id().toString()).expiresAt(Instant.now().plusSeconds(60)).claim("ver",3).build(),
            JwtClaimsSet.builder().issuer("issuer").audience(List.of("audience")).subject(account.id().toString()).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build());
        for(var claims:cases) assertThrows(JwtException.class,() -> decoder().decode(token(claims)));
        var valid=token(claims().build()); var parts=valid.split("\\.");
        assertThrows(JwtException.class,() -> decoder().decode(parts[0]+"."+parts[1]+".AAAA"));
        assertThrows(JwtException.class,() -> decoder().decode("invalid"));
    }
    @Test void readsPemAndConstructsCentralizedBeans() throws Exception {
        assertEquals("bearer",config.openApi().getComponents().getSecuritySchemes().get("bearerAuth").getScheme());
        assertEquals("X-Service-Key",config.openApi().getComponents().getSecuritySchemes().get("serviceKey").getName());
        String pub="-----BEGIN PUBLIC KEY-----\n"+Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())+"\n-----END PUBLIC KEY-----";
        String priv="-----BEGIN PRIVATE KEY-----\n"+Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())+"\n-----END PRIVATE KEY-----";
        assertEquals(pair.getPublic(),config.publicKey(new ByteArrayResource(pub.getBytes())));
        assertEquals(pair.getPrivate(),config.privateKey(new ByteArrayResource(priv.getBytes())));
        var service=mock(IdentityService.class);
        config.bootstrap(service,false,"n","e","p").run(null); verifyNoInteractions(service);
        config.bootstrap(service,true,"n","e","p").run(null); verify(service).bootstrap("n","e","p");
        var gateway=config.accountGateway(mock(SpringAccountRepository.class),config.accountMapper(),mock(JdbcTemplate.class),mock(PlatformTransactionManager.class));
        assertNotNull(config.identityService(gateway,mock(PasswordGateway.class),mock(TokenGateway.class),config.clock()));
    }
    @Test void internalAuthenticationAndCurrentCredentialsAreMandatory() {
        var service=mock(IdentityService.class); String key="x".repeat(32);
        var access=config.tokenAccess(service,decoder(),key);
        when(service.current(account.id(),3)).thenReturn(account);
        var jwt=decoder().decode(token(claims().build()));
        assertEquals(account,access.current(jwt)); assertEquals(account,access.validate(key,jwt.getTokenValue()));
        assertEquals(IdentityException.Code.SERVICE_UNAUTHORIZED,assertThrows(IdentityException.class,() -> access.validate(null,jwt.getTokenValue())).code());
        assertEquals(IdentityException.Code.SERVICE_UNAUTHORIZED,assertThrows(IdentityException.class,() -> access.validate("bad",jwt.getTokenValue())).code());
        assertEquals(IdentityException.Code.UNAUTHORIZED,assertThrows(IdentityException.class,() -> access.validate(key,"bad")).code());
        assertThrows(IdentityException.class,() -> access.validate(key,null));
        assertThrows(IllegalArgumentException.class,() -> new TokenAccess(service,decoder(),"short"));
        assertThrows(IllegalArgumentException.class,() -> new TokenAccess(service,decoder(),null));
        assertThrows(IdentityException.class,() -> access.current(null));
        when(service.current(account.id(),3)).thenThrow(new IdentityException(IdentityException.Code.UNAUTHORIZED));
        assertThrows(IdentityException.class,() -> access.validate(key,jwt.getTokenValue()));
        var malformed=Jwt.withTokenValue("t").header("alg","RS256").subject("bad").claim("ver",1).build();
        assertThrows(IdentityException.class,() -> access.current(malformed));
    }
}
