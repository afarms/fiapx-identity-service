package br.com.fiap.fiapx.identity.core;
import br.com.fiap.fiapx.identity.core.domain.*;
import br.com.fiap.fiapx.identity.core.domain.Account.Role;
import br.com.fiap.fiapx.identity.core.gateway.*;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import static br.com.fiap.fiapx.identity.core.exception.IdentityException.Code.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.time.*;
import java.util.*;
import java.util.function.Supplier;
class IdentityServiceTest {
    final Map<UUID,Account> db=new HashMap<>();
    final AccountGateway gateway=mock(AccountGateway.class);
    final PasswordGateway passwords=mock(PasswordGateway.class);
    final TokenGateway tokens=mock(TokenGateway.class);
    final Clock clock=Clock.fixed(Instant.parse("2026-09-24T12:00:00Z"),ZoneOffset.UTC);
    IdentityService service;
    final String password="a-good-password";
    @BeforeEach void setup() {
        when(passwords.hash(anyString())).thenAnswer(i -> "hash:"+i.getArgument(0));
        when(passwords.matches(any(),anyString())).thenAnswer(i -> ("hash:"+i.getArgument(0)).equals(i.getArgument(1)));
        when(gateway.locked(any())).thenAnswer(i -> ((Supplier<?>)i.getArgument(0)).get());
        when(gateway.findById(any())).thenAnswer(i -> Optional.ofNullable(db.get(i.getArgument(0))));
        when(gateway.findByEmail(anyString())).thenAnswer(i -> db.values().stream().filter(a -> a.email().equals(i.getArgument(0))).findFirst());
        when(gateway.save(any())).thenAnswer(i -> { Account a=i.getArgument(0); db.put(a.id(),a); return a; });
        when(gateway.countActiveAdmins()).thenAnswer(i -> db.values().stream().filter(a -> a.active() && a.role()==Role.ADMIN).count());
        when(tokens.issue(any())).thenReturn("signed");
        service=new IdentityService(gateway,passwords,tokens,clock);
    }
    Account user() { return service.register(" Name "," USER@Example.com ",password); }
    Account admin() { service.bootstrap("Admin","admin@example.com",password); return db.values().stream().filter(a -> a.role()==Role.ADMIN).findFirst().orElseThrow(); }
    void error(IdentityException.Code code,org.junit.jupiter.api.function.Executable action) { assertEquals(code,assertThrows(IdentityException.class,action).code()); }
    @Test void registrationNormalizesAndNeverStoresRawPasswordOrAcceptsDuplicate() {
        var a=user(); assertEquals("Name",a.name()); assertEquals("user@example.com",a.email());
        assertEquals(Role.USER,a.role()); assertTrue(a.active()); assertEquals(0,a.credentialVersion());
        assertEquals(clock.instant(),a.createdAt()); assertEquals("hash:"+password,a.passwordHash());
        assertFalse(a.toString().contains(password));
        error(CONFLICT,this::user);
        assertEquals("signed",service.login("USER@EXAMPLE.COM",password));
    }
    @Test void loginUsesSameErrorForAbsentWrongPasswordInactiveAndInvalidEmail() {
        var a=user();
        error(UNAUTHORIZED,() -> service.login("missing@example.com",password));
        error(UNAUTHORIZED,() -> service.login(a.email(),"wrong"));
        error(UNAUTHORIZED,() -> service.login("invalid",password));
        error(UNAUTHORIZED,() -> service.login(null,null));
        db.put(a.id(),a.permissions(Role.USER,false));
        error(UNAUTHORIZED,() -> service.login(a.email(),password));
    }
    @Test void currentRejectsAbsentRevokedAndDisabledAccounts() {
        var a=user(); assertEquals(a,service.current(a.id(),0));
        error(UNAUTHORIZED,() -> service.current(UUID.randomUUID(),0));
        error(UNAUTHORIZED,() -> service.current(a.id(),1));
        db.put(a.id(),a.permissions(Role.USER,false));
        error(FORBIDDEN,() -> service.current(a.id(),1));
    }
    @Test void changesCredentialsAtomicallyRevokesTokenAndPreservesId() {
        var a=user(); var renamed=service.profile(a.id(),0,"New name");
        assertEquals("New name",renamed.name());
        service.credentials(a.id(),0,password,"NEW@example.com","new-good-password");
        var updated=db.get(a.id()); assertEquals(1,updated.credentialVersion()); assertEquals("new@example.com",updated.email());
        error(UNAUTHORIZED,() -> service.current(a.id(),0));
        assertEquals("signed",service.login(updated.email(),"new-good-password"));
        service.credentials(a.id(),1,"new-good-password","new@example.com","third-password");
        assertEquals(2,db.get(a.id()).credentialVersion());
    }
    @Test void wrongCurrentPasswordOrEmailCollisionCannotMutateAccount() {
        var a=user(); service.register("Other","other@example.com",password);
        error(UNAUTHORIZED,() -> service.credentials(a.id(),0,"wrong","new@example.com",password));
        error(CONFLICT,() -> service.credentials(a.id(),0,password,"other@example.com",password));
        assertEquals(a,db.get(a.id()));
    }
    @Test void adminMutationsProtectLastAdminAndRecheckActorVersionAndRole() {
        var a=admin(); var u=user();
        error(FORBIDDEN,() -> service.permissions(u.id(),0,a.id(),Role.USER,true));
        error(CONFLICT,() -> service.permissions(a.id(),0,a.id(),Role.USER,true));
        error(CONFLICT,() -> service.permissions(a.id(),0,a.id(),Role.ADMIN,false));
        error(NOT_FOUND,() -> service.permissions(a.id(),0,UUID.randomUUID(),Role.USER,true));
        assertThrows(NullPointerException.class,() -> service.permissions(a.id(),0,u.id(),null,true));
        var unchanged=service.permissions(a.id(),0,a.id(),Role.ADMIN,true); assertEquals(0,unchanged.credentialVersion());
        service.permissions(a.id(),0,u.id(),Role.ADMIN,true);
        service.permissions(a.id(),0,a.id(),Role.USER,true);
        error(FORBIDDEN,() -> service.permissions(a.id(),0,u.id(),Role.USER,true));
        service.permissions(u.id(),0,a.id(),Role.USER,false);
        service.permissions(u.id(),0,a.id(),Role.USER,true);
        assertEquals(2,db.get(a.id()).credentialVersion());
        error(UNAUTHORIZED,() -> service.current(a.id(),0));
        assertEquals(Role.USER,service.current(a.id(),2).role());
    }
    @Test void listsOnlyForAdminAndValidatesPagination() {
        var a=admin(); var u=user();
        var page=new AccountPage(List.of(a,u),0,20,2);
        when(gateway.list(0,20)).thenReturn(page);
        assertEquals(page,service.list(a.id(),0,0,20));
        error(FORBIDDEN,() -> service.list(u.id(),0,0,20));
        assertAll(
            () -> assertThrows(IllegalArgumentException.class,() -> service.list(a.id(),0,-1,20)),
            () -> assertThrows(IllegalArgumentException.class,() -> service.list(a.id(),0,0,0)),
            () -> assertThrows(IllegalArgumentException.class,() -> service.list(a.id(),0,0,101)));
        assertThrows(UnsupportedOperationException.class,() -> page.items().clear());
    }
    @Test void bootstrapIdempotentAndDoesNotPromoteOrOverwriteExistingAccounts() {
        var u=user(); error(CONFLICT,() -> service.bootstrap("Admin",u.email(),password));
        var a=admin(); service.bootstrap("Different",a.email(),"other-password");
        assertEquals(a,db.get(a.id()));
        service.bootstrap("Different","different@example.com",password); assertEquals(2,db.size());
        db.put(a.id(),a.permissions(Role.ADMIN,false));
        error(CONFLICT,() -> service.bootstrap("Admin",a.email(),password));
    }
    @ParameterizedTest @NullAndEmptySource @ValueSource(strings={" ","a","no-at-sign","a@b","x@x.x y","a@@b.com"})
    void rejectsBadEmails(String email) { assertThrows(IllegalArgumentException.class,() -> Account.normalizeEmail(email)); }
    @Test void rejectsLongEmailNameAndBadDomainState() {
        assertThrows(IllegalArgumentException.class,() -> Account.normalizeEmail("x".repeat(250)+"@a.com"));
        for(String name:Arrays.asList(null,""," ","x".repeat(101))) assertThrows(IllegalArgumentException.class,() -> Account.validName(name));
        var a=user();
        assertThrows(IllegalArgumentException.class,() -> new Account(a.id(),a.name(),a.email(),null,Role.USER,true,0,clock.instant()));
        assertThrows(IllegalArgumentException.class,() -> new Account(a.id(),a.name(),a.email()," ",Role.USER,true,0,clock.instant()));
        assertThrows(IllegalArgumentException.class,() -> new Account(a.id(),a.name(),a.email(),"hash",Role.USER,true,-1,clock.instant()));
        assertThrows(NullPointerException.class,() -> new Account(null,a.name(),a.email(),"hash",Role.USER,true,0,clock.instant()));
    }
    @Test void passwordBoundariesAndNullDependencies() {
        for(String p:Arrays.asList(null,"","short","x".repeat(73),"é".repeat(37))) assertThrows(IllegalArgumentException.class,() -> IdentityService.checkPassword(p));
        IdentityService.checkPassword("x".repeat(12)); IdentityService.checkPassword("x".repeat(72)); IdentityService.checkPassword("é".repeat(36));
        assertThrows(NullPointerException.class,() -> new IdentityService(null,passwords,tokens,clock));
        assertThrows(NullPointerException.class,() -> new IdentityService(gateway,null,tokens,clock));
        assertThrows(NullPointerException.class,() -> new IdentityService(gateway,passwords,null,clock));
        assertThrows(NullPointerException.class,() -> new IdentityService(gateway,passwords,tokens,null));
    }
}
