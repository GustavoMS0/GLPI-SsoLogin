# Changelog

Todas as mudanças relevantes deste projeto serão documentadas neste arquivo.

## [1.0.0] - 2026-11-16

### Adicionado
- Autenticação Single Sign-On via OpenID Connect / OAuth 2.0 Authorization Code Flow com PKCE (`S256`).
- Validação anti-SSRF estrita para endpoints do provedor de identidade (`https://` obrigatório e bloqueio de loopback, link-local `169.254.169.254` e redes privadas RFC1918).
- Criptografia autenticada em repouso (`AES-256-GCM`) para `client_secret` e proteção via hook `undiscloseConfigValue`.
- Consumo atômico e de uso único de `state` e `nonce` na sessão (`$_SESSION['plugin_ssologin_flow']`) com proteção contra replay e open redirect.
- Resolução segura e inequívoca de usuários ativos em `glpi_users` e `glpi_useremails` com verificação de vigência e perfis ativos.
- Botão de autenticação SSO integrado à tela de login (`display_login`) e trilha de auditoria em `glpi_plugin_ssologin_logs`.
- Suporte unificado para GLPI `10.0.0` a `12.0.99` e PHP `7.4` a `8.3+`.
