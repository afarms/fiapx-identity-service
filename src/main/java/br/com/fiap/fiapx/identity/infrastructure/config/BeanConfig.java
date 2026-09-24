package br.com.fiap.fiapx.identity.infrastructure.config;
import br.com.fiap.fiapx.identity.core.gateway.*;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.infrastructure.persistence.adapter.AccountGatewayAdapter;
import br.com.fiap.fiapx.identity.infrastructure.persistence.mapper.AccountMapper;
import br.com.fiap.fiapx.identity.infrastructure.persistence.repository.SpringAccountRepository;
import br.com.fiap.fiapx.identity.infrastructure.security.*;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.time.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;
@Configuration(proxyBeanMethods=false)
public class BeanConfig {
    @Bean public io.swagger.v3.oas.models.OpenAPI openApi() {
        return new io.swagger.v3.oas.models.OpenAPI().components(new io.swagger.v3.oas.models.Components()
            .addSecuritySchemes("bearerAuth",new io.swagger.v3.oas.models.security.SecurityScheme().type(io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT"))
            .addSecuritySchemes("serviceKey",new io.swagger.v3.oas.models.security.SecurityScheme().type(io.swagger.v3.oas.models.security.SecurityScheme.Type.APIKEY).in(io.swagger.v3.oas.models.security.SecurityScheme.In.HEADER).name("X-Service-Key")));
    }
    @Bean public Clock clock() { return Clock.systemUTC(); }
    @Bean public AccountMapper accountMapper() { return new AccountMapper(); }
    @Bean public AccountGateway accountGateway(SpringAccountRepository repository,AccountMapper mapper,JdbcTemplate jdbc,PlatformTransactionManager tm) {
        return new AccountGatewayAdapter(repository,mapper,jdbc,new TransactionTemplate(tm));
    }
    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }
    @Bean public PasswordGateway passwordGateway(PasswordEncoder encoder) { return new PasswordAdapter(encoder); }
    @Bean public RSAPublicKey publicKey(@Value("${identity.jwt.public-key}") Resource file) throws Exception {
        try(var input=file.getInputStream()) { return RsaKeyConverters.x509().convert(input); }
    }
    @Bean public RSAPrivateKey privateKey(@Value("${identity.jwt.private-key}") Resource file) throws Exception {
        try(var input=file.getInputStream()) { return RsaKeyConverters.pkcs8().convert(input); }
    }
    @Bean public JwtEncoder jwtEncoder(RSAPublicKey publicKey,RSAPrivateKey privateKey) {
        var key=new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("identity-v1").build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }
    @Bean public JwtDecoder jwtDecoder(RSAPublicKey key,@Value("${identity.jwt.issuer}") String issuer,
            @Value("${identity.jwt.audience}") String audience) {
        var decoder=NimbusJwtDecoder.withPublicKey(key).build();
        OAuth2TokenValidator<Jwt> contract=jwt -> {
            try {
                UUID.fromString(jwt.getSubject());
                var version=jwt.getClaim("ver");
                if (!(version instanceof Long || version instanceof Integer) || ((Number)version).longValue()<0
                    || jwt.getExpiresAt()==null || jwt.getIssuedAt()==null || !jwt.getAudience().contains(audience)
                    || !jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
                    || Duration.between(jwt.getIssuedAt(),jwt.getExpiresAt()).getSeconds()>1800
                    || jwt.getIssuedAt().isAfter(Instant.now().plusSeconds(30))) throw new IllegalArgumentException();
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException e) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
            }
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(Duration.ZERO),new JwtIssuerValidator(issuer),contract));
        return decoder;
    }
    @Bean public TokenGateway tokenGateway(JwtEncoder encoder,Clock clock,@Value("${identity.jwt.issuer}") String issuer,
            @Value("${identity.jwt.audience}") String audience) { return new JwtTokenAdapter(encoder,clock,issuer,audience); }
    @Bean public IdentityService identityService(AccountGateway accounts,PasswordGateway passwords,TokenGateway tokens,Clock clock) {
        return new IdentityService(accounts,passwords,tokens,clock);
    }
    @Bean public TokenAccess tokenAccess(IdentityService service,JwtDecoder decoder,@Value("${identity.service-key}") String key) {
        return new TokenAccess(service,decoder,key);
    }
    @Bean public ApplicationRunner bootstrap(IdentityService service,@Value("${identity.bootstrap.enabled:false}") boolean enabled,
            @Value("${identity.bootstrap.name:Administrator}") String name,@Value("${identity.bootstrap.email:}") String email,
            @Value("${identity.bootstrap.password:}") String password) {
        return args -> { if(enabled) service.bootstrap(name,email,password); };
    }
    @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a.requestMatchers("/auth/register","/auth/login","/internal/accounts/validate",
                "/actuator/health/**","/swagger-ui.html","/swagger-ui/**","/v3/api-docs/**","/error").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(o -> o.jwt(j -> {})).build();
    }
}
