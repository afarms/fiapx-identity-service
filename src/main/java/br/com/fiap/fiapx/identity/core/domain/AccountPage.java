package br.com.fiap.fiapx.identity.core.domain;
import java.util.List;
public record AccountPage(List<Account> items, int page, int size, long totalElements) {
    public AccountPage { items = List.copyOf(items); }
}
