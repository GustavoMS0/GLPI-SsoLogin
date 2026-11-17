# SSO Login (`ssologin`) — Plugin para GLPI 10 / 11 / 12

> [!WARNING]
> **Status: Em Desenvolvimento (Beta / Pré-homologação)**
> Este plugin teve a arquitetura, a segurança e os fluxos validados por revisão de código, auditoria de segurança e testes unitários automatizados em CI (`PHP 7.4–8.3` com mocks de GLPI 10/11/12), mas **ainda não foi testado em uma instância GLPI ao vivo**. Valide em ambiente de homologação antes de usar em produção e reporte eventuais ajustes via Issues.

Autenticação **Single Sign-On (OpenID Connect / OAuth 2.0 com PKCE `S256`)** para o GLPI, compatível com **Microsoft Entra ID (Azure AD)**, **Keycloak**, **Google Workspace**, **Okta**, **Authentik** e provedores OIDC padrão.

---

## Principais Funcionalidades

- **Fluxo Authorization Code + PKCE (`S256`):** geração criptograficamente segura de `state`, `nonce` e par `code_verifier` / `code_challenge` (`SHA-256` Base64URL).
- **Anti-Replay Estrito (`state` de uso único):** o estado da sessão (`$_SESSION['plugin_ssologin_flow']`) é consumido e invalidado imediatamente na primeira resposta ao callback, com expiração máxima de 10 minutos (`600`s).
- **Proteção Anti-SSRF nos Endpoints:** exige esquema `https://`, bloqueia credenciais embutidas na URL e rejeita endereços de loopback (`127.0.0.0/8`, `::1`, `localhost`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`) e redes privadas RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) tanto em IPs literais quanto na resolução DNS.
- **Validação de `id_token` e `userinfo`:** verifica assinatura HMAC (`HS256`) quando aplicável, emissor (`iss`), audiência (`aud` / `azp`), validade temporal (`exp` / `nbf` com tolerância de 60s), `nonce` com `hash_equals()`, correspondência de `sub` no endpoint `userinfo` e exigência de `email_verified !== false`.
- **Segredo Cifrado em Repouso (`AES-256-GCM`):** o `client_secret` é cifrado via `openssl_encrypt` (`aes-256-gcm` com tag autenticada de 128 bits), protegido no hook `undiscloseConfigValue` e jamais é reexibido no HTML da página de configuração.
- **Mapeamento Inequívoco de Conta GLPI:** vincula por `glpi_users.name` e/ou `glpi_useremails.email`. Caso mais de um usuário ativo compartilhe o mesmo identificador ou e-mail, o login é recusado (fail-closed) para impedir tomada de conta.
- **Proteção contra Open Redirect:** valida estritamente o caminho de redirecionamento pós-login, aceitando apenas rotas internas relativas ao GLPI.
- **Trilha de Auditoria:** grava eventos de autenticação e falhas de validação na tabela `glpi_plugin_ssologin_logs` com expurgo configurável.

---

## Matriz de Compatibilidade

| Série do GLPI | Versões Suportadas | Versão do PHP |
| :--- | :--- | :--- |
| **GLPI 10** | `10.0.0` – `10.0.99` | PHP `7.4+` (`7.4` a `8.3`) |
| **GLPI 11** | `11.0.0` – `11.0.99` | PHP `8.2+` (`8.2` a `8.3+`) |
| **GLPI 12** | `12.0.0-dev` – `12.0.99` | PHP `8.3+` |

---

## Instalação

1. Copie a pasta `ssologin` para o diretório `plugins/ssologin` (ou `marketplace/ssologin` no GLPI 10) da sua instalação do GLPI.
2. Acesse **Configurar > Plugins** no GLPI, localize **SSO Login** (`ssologin`), clique em **Instalar** e em seguida em **Ativar**.
3. Acesse a página de configuração do plugin (`front/config.form.php`), copie a **URI de Callback / Redirecionamento** exibida e cadastre-a no seu Provedor de Identidade (IdP).
4. Preencha o `Client ID`, `Client Secret` e as URLs HTTPS (`Authorization`, `Token`, `UserInfo` e `Issuer`) e salve.

---

## Execução de Testes

```bash
php tests/run.php
```

---

## Licença e Autoria

- **Autor:** G. Martins
- **Licença:** GNU General Public License v3.0 or later (`GPL-3.0-or-later` / `GPLv3+`)
- Copyright (C) 2026 by G. Martins
