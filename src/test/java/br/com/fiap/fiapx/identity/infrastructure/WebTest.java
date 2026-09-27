package br.com.fiap.fiapx.identity.infrastructure;
import br.com.fiap.fiapx.identity.core.domain.*;
import br.com.fiap.fiapx.identity.core.usecase.IdentityService;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import br.com.fiap.fiapx.identity.infrastructure.web.*;
import br.com.fiap.fiapx.identity.infrastructure.web.IdentityController.*;
import br.com.fiap.fiapx.identity.infrastructure.security.TokenAccess;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.time.Instant;
class WebTest {
    @Test void publicResponsesDoNotExposePasswordOrCredentialVersionAndRoutesDelegateOwnership() {
        var service=mock(IdentityService.class); var access=mock(TokenAccess.class); var controller=new IdentityController(service,access);
        var a=new Account(UUID.randomUUID(),"User","user@example.com","private-hash",Account.Role.USER,true,7,Instant.now());
        when(service.register("User",a.email(),"password")).thenReturn(a);
        assertEquals(a.id(),controller.register(new Registration("User",a.email(),"password")).id());
        when(service.login(a.email(),"password")).thenReturn("token");
        assertEquals(new TokenResponse("token","Bearer",1800),controller.login(new Login(a.email(),"password")));
        when(access.current(null)).thenReturn(a); assertEquals(a.email(),controller.me(null).email());
        assertFalse(controller.me(null).toString().contains("private-hash"));
        when(service.profile(a.id(),7,"New")).thenReturn(a.profile("New"));
        assertEquals("New",controller.profile(null,new Profile("New")).name());
        controller.credentials(null,new Credentials("old","new@example.com","new-password"));
        verify(service).credentials(a.id(),7,"old","new@example.com","new-password");
        when(service.list(a.id(),7,0,20)).thenReturn(new AccountPage(List.of(a),0,20,1));
        assertEquals(1,controller.list(null,0,20).totalElements());
        when(service.permissions(a.id(),7,a.id(),Account.Role.ADMIN,true)).thenReturn(a.permissions(Account.Role.ADMIN,true));
        assertEquals(Account.Role.ADMIN,controller.permissions(null,a.id(),new Permissions(Account.Role.ADMIN,true)).role());
        assertThrows(IllegalArgumentException.class,() -> controller.permissions(null,a.id(),new Permissions(null,true)));
        assertThrows(IllegalArgumentException.class,() -> controller.permissions(null,a.id(),new Permissions(Account.Role.ADMIN,null)));
        when(access.validate("key","token")).thenReturn(a);
        assertEquals(new AccessResponse(a.id(),a.role(),true,7),controller.validate("key",new TokenRequest("token")));
    }
    @Test void errorResponsesAreSanitized() {
        var errors=new ApiErrors();
        int[] expected={401,403,404,409,503,401}; int index=0;
        for(var code:IdentityException.Code.values()) {
            var response=errors.identity(new IdentityException(code,new RuntimeException("secret")));
            assertEquals(expected[index++],response.getStatusCode().value());
            assertEquals(code.name(),response.getBody().getProperties().get("code"));
            assertFalse(response.getBody().toString().contains("secret"));
        }
        assertEquals(400,errors.invalid(new IllegalArgumentException("secret")).getStatusCode().value());
    }
}
