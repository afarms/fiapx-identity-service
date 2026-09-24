package br.com.fiap.fiapx.identity.infrastructure.web;
import br.com.fiap.fiapx.identity.core.domain.Account;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.infrastructure.security.TokenAccess;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.HttpStatus;
import java.util.*;
import java.time.Instant;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
@RestController
public class IdentityController {
    private final IdentityService service; private final TokenAccess access;
    public IdentityController(IdentityService service,TokenAccess access) { this.service=service; this.access=access; }
    public record Registration(String name,String email,String password) {}
    public record Login(String email,String password) {}
    public record Credentials(String currentPassword,String email,String newPassword) {}
    public record Profile(String name) {}
    public record Permissions(Account.Role role,Boolean active) {}
    public record TokenRequest(String token) {}
    public record TokenResponse(String accessToken,String tokenType,long expiresIn) {}
    public record UserResponse(UUID id,String name,String email,Account.Role role,boolean active,Instant createdAt) {
        static UserResponse from(Account a) { return new UserResponse(a.id(),a.name(),a.email(),a.role(),a.active(),a.createdAt()); }
    }
    public record UserPage(List<UserResponse> items,int page,int size,long totalElements) {}
    public record AccessResponse(UUID id,Account.Role role,boolean active,long credentialVersion) {}
    @PostMapping("/auth/register") @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@RequestBody Registration r) { return UserResponse.from(service.register(r.name(),r.email(),r.password())); }
    @PostMapping("/auth/login")
    public TokenResponse login(@RequestBody Login r) { return new TokenResponse(service.login(r.email(),r.password()),"Bearer",1800); }
    @GetMapping("/users/me")
    @SecurityRequirement(name="bearerAuth")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) { return UserResponse.from(access.current(jwt)); }
    @PatchMapping("/users/me")
    @SecurityRequirement(name="bearerAuth")
    public UserResponse profile(@AuthenticationPrincipal Jwt jwt,@RequestBody Profile r) {
        var actor=access.current(jwt);
        return UserResponse.from(service.profile(actor.id(),actor.credentialVersion(),r.name()));
    }
    @PutMapping("/users/me/credentials") @ResponseStatus(HttpStatus.NO_CONTENT)
    @SecurityRequirement(name="bearerAuth")
    public void credentials(@AuthenticationPrincipal Jwt jwt,@RequestBody Credentials r) {
        var actor=access.current(jwt);
        service.credentials(actor.id(),actor.credentialVersion(),r.currentPassword(),r.email(),r.newPassword());
    }
    @GetMapping("/admin/users")
    @SecurityRequirement(name="bearerAuth")
    public UserPage list(@AuthenticationPrincipal Jwt jwt,@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size) {
        var actor=access.current(jwt);
        var result=service.list(actor.id(),actor.credentialVersion(),page,size);
        return new UserPage(result.items().stream().map(UserResponse::from).toList(),result.page(),result.size(),result.totalElements());
    }
    @PatchMapping("/admin/users/{id}")
    @SecurityRequirement(name="bearerAuth")
    public UserResponse permissions(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@RequestBody Permissions r) {
        if(r.role()==null || r.active()==null) throw new IllegalArgumentException("role and active required");
        var actor=access.current(jwt);
        return UserResponse.from(service.permissions(actor.id(),actor.credentialVersion(),id,r.role(),r.active()));
    }
    @PostMapping("/internal/accounts/validate")
    @SecurityRequirement(name="serviceKey")
    public AccessResponse validate(@RequestHeader(value="X-Service-Key",required=false) String key,@RequestBody TokenRequest r) {
        var a=access.validate(key,r.token());
        return new AccessResponse(a.id(),a.role(),a.active(),a.credentialVersion());
    }
}
