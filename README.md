# FIAP X — Identidade

Entrada cloud preparada: /api/identity/ no endereço CloudFront, Swagger em /api/identity/swagger-ui.html. O Service NodePort30081 é privado e mantém porta8080 para chamadas internas. SERVER_FORWARD_HEADERS_STRATEGY=framework interpreta os cabeçalhos normalizados pela borda. A URL real e a ordem de ativação estão no [runbook de infraestrutura](https://github.com/afarms/fiapx-infra/blob/main/docs/operations/public-api.md); dependem do apply.

Serviço independente de cadastro, autenticação e autorização de contas. Java 21, Spring Boot 4.1.1, PostgreSQL 17, Liquibase SQL e Clean Architecture. Core sem Spring; infraestrutura com entity/mapper/adapter/repository e composição em BeanConfig.

## Executar localmente

Requer JDK 21, Git Bash, GNU Make e Rancher Desktop com engine Moby. O Wrapper baixa Maven 3.9.16; manter mvnw e .mvn versionados.

```bash
cp .env.example .env
make keys
```

Preencher `.env`: DB_PASSWORD, IDENTITY_SERVICE_KEY (segredo aleatório com pelo menos 32 caracteres), BOOTSTRAP_ADMIN_EMAIL e BOOTSTRAP_ADMIN_PASSWORD (12 caracteres ou mais, até 72 bytes UTF-8). Não reutilizar senhas pessoais. Valores com espaços/caracteres especiais precisam de aspas compatíveis com Bash. `.env` e `.local/keys` são ignorados pelo Git. `make keys` gera um par RSA de 3072 bits e recusa sobrescrever arquivos existentes.

```bash
make verify
make up
```

PostgreSQL em localhost:5433, API em localhost:8081, Swagger em http://localhost:8081/swagger-ui.html e OpenAPI em http://localhost:8081/v3/api-docs. Portas podem ser alteradas no `.env`. `make down` preserva o volume. Não apagar o volume para reiniciar o serviço.

Para executar Java no host: iniciar somente o PostgreSQL com `docker compose up -d postgres` e executar `make run`. Não executar simultaneamente host e container na mesma porta. `make run` carrega `.env`; `make package` empacota, `make install` também instala no cache Maven.

## Comportamento

- Cadastro: nome, e-mail único e senha; cria USER ativo imediatamente, sem confirmar posse do e-mail. E-mail recebe trim/lowercase; senha não recebe trim.
- Login: e-mail e senha; JWT RS256 de 30 minutos, sem refresh. Consumidor deve manter token em memória e pedir novo login após reload/expiração.
- Perfil: usuário consulta seus dados e altera seu nome. Mudança de e-mail e senha exige senha atual e invalida todos os tokens anteriores, preservando UUID e dados vinculados.
- Administração: listar contas, mudar papel e ativar/inativar. O último ADMIN ativo não pode ser rebaixado/inativado. Mudança de papel tem efeito nas próximas autorizações; inativação e reativação não revalidam tokens antigos.
- Bootstrap: com BOOTSTRAP_ADMIN_ENABLED=true, cria administrador se não houver ADMIN ativo. Nunca sobrescreve senha de conta existente; colisão com USER ou conta inativa falha explicitamente. Depois do primeiro provisionamento pode ser desabilitado.

Escritas usam transação com advisory lock PostgreSQL do domínio, para serializar bootstrap e proteção do último admin. É uma escolha simples para o volume acadêmico, não uma promessa de alta vazão de escrita.

## Contrato HTTP

| Método e rota | Acesso | Resultado |
| --- | --- | --- |
| POST /auth/register | Público | 201; perfil sem hash |
| POST /auth/login | Público | 200; accessToken, tokenType=Bearer, expiresIn=1800 |
| GET /users/me | JWT e conta ativa | Perfil próprio |
| PATCH /users/me | JWT e conta ativa | Corpo name; perfil atualizado |
| PUT /users/me/credentials | JWT e senha atual | Corpo currentPassword, email, newPassword; 204, novo login |
| GET /admin/users?page=0&size=20 | ADMIN ativo | Página de contas, tamanho 1–100 |
| PATCH /admin/users/{id} | ADMIN ativo | Corpo role (USER/ADMIN), active (boolean) |
| POST /internal/accounts/validate | X-Service-Key | Corpo token; retorna id, role, active, credentialVersion |

Credenciais incorretas/ausentes, assinatura inválida e token revogado retornam 401; papel insuficiente/conta bloqueada 403 (inativação também revoga token e pode produzir 401); conta alvo ausente 404; conflito de e-mail/último admin 409; payload inválido 400; falha de persistência 503. Campos desconhecidos no JSON são rejeitados, inclusive role/active no cadastro.

## Integração e chaves

Erros de domínio incluem `code` no ProblemDetail. Na validação interna, HTTP 401 com `SERVICE_UNAUTHORIZED` indica credencial do serviço ausente/incorreta; `UNAUTHORIZED` indica token do usuário inválido/revogado. O consumidor deve apresentar 503 para falha da credencial de serviço e 401 para token do usuário. HTTP 403 com `FORBIDDEN` indica conta bloqueada. Respostas inesperadas ou sem código reconhecido não autorizam acesso.

Issuer padrão `fiapx-identity`, audience `fiapx-api`, sub UUID, claim `ver` com versão de credenciais. JWT_ISSUER/JWT_AUDIENCE configuráveis; JWT_PRIVATE_KEY/JWT_PUBLIC_KEY são recursos PEM PKCS#8/X.509. Chaves persistem fora da imagem e do Git; a privada pertence somente à identidade. Configurar leitura pelo UID 10001 em montagens Linux e usar HTTPS na implantação. Rotação coordenada/manual ainda não possui JWKS automatizado.

Após validar assinatura/issuer/audience/tempo, o consumidor deve consultar `/internal/accounts/validate` com seu segredo de serviço e o token completo a cada nova operação protegida, sem cache positivo. A resposta usa conta/papel/versão atuais; uma indisponibilidade deve impedir autorização, normalmente com 503. A integração do serviço de vídeos ainda será implementada. Contrato customizado: este serviço não anuncia compatibilidade com OAuth Authorization Server/OIDC.

O uso de JWT no Spring segue a [documentação oficial do Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html). Senhas usam BCrypt custo 12; hash e credenciais não são retornados nos perfis. Não registrar bodies de login, troca de senha ou validação interna. API usa Bearer stateless, sem sessão/cookie de autenticação. CORS não é aberto genericamente. Limitação de tentativas de login deve ser configurada antes de exposição pública; não há rate limiter distribuído neste incremento.

## Testes e imagem

`make verify` roda JUnit/Mockito, compilação isolada do core e JaCoCo com mínimo 90% de linhas e branches; somente o launcher é excluído. Relatórios em target/surefire-reports e target/site/jacoco. CI preparada para PR/main: unit-tests seguido de container-build; exigir ambos na proteção da main. Execução remota depende da criação do repositório GitHub.

Docker multi-stage JDK → JRE Alpine, usuário 10001, runtime somente leitura e healthcheck de readiness. O Dockerfile empacota com testes pulados; CI testa antes de construir a imagem. Não há publicação ou deploy automático.

Fora deste incremento: recuperação de senha por e-mail, exclusão distribuída de contas/dados, filas e integração com consumidores. Nenhuma rota DELETE está disponível; desativar preserva o cadastro e não equivale a excluir.
