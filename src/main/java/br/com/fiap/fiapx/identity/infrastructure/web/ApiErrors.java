package br.com.fiap.fiapx.identity.infrastructure.web;
import br.com.fiap.fiapx.identity.core.exception.IdentityException;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(IdentityException.class)
    public ResponseEntity<ProblemDetail> identity(IdentityException exception) {
        var status=switch(exception.code()) {
            case UNAUTHORIZED, SERVICE_UNAUTHORIZED -> HttpStatus.UNAUTHORIZED; case FORBIDDEN -> HttpStatus.FORBIDDEN;
            case NOT_FOUND -> HttpStatus.NOT_FOUND; case CONFLICT -> HttpStatus.CONFLICT; case UNAVAILABLE -> HttpStatus.SERVICE_UNAVAILABLE;
        };
        var problem=ProblemDetail.forStatusAndDetail(status,status.getReasonPhrase());
        problem.setProperty("code",exception.code().name());
        return ResponseEntity.status(status).body(problem);
    }
    @ExceptionHandler({IllegalArgumentException.class,HttpMessageNotReadableException.class})
    public ResponseEntity<ProblemDetail> invalid(Exception exception) {
        return ResponseEntity.badRequest().body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,"Invalid request"));
    }
}
