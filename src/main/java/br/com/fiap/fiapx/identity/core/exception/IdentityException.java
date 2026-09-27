package br.com.fiap.fiapx.identity.core.exception;
public class IdentityException extends RuntimeException {
    public enum Code { UNAUTHORIZED, FORBIDDEN, NOT_FOUND, CONFLICT, UNAVAILABLE }
    private final Code code;
    public IdentityException(Code code) { super(code.name()); this.code = code; }
    public IdentityException(Code code, Throwable cause) { super(code.name(),cause); this.code = code; }
    public Code code() { return code; }
}
