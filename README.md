# GB | Sistema de gestão para barbearia

Projeto prático do curso Técnico em Desenvolvimento de Sistemas. O sistema reúne autenticação, cadastro de clientes e barbeiros, catálogo de serviços e agendamentos com validação de conflito de horários.

## Requisitos funcionais

- RF01: autenticar usuários com validação de credenciais e mensagem de erro.
- RF02: manter sessão autenticada com expiração após 30 minutos e permitir logout.
- RF03: exibir painel com identificação do usuário, indicadores e próximos atendimentos.
- RF04: cadastrar, consultar, editar e excluir clientes; filtrar a listagem por nome, telefone ou e-mail.
- RF05: cadastrar, consultar, editar e excluir barbeiros.
- RF06: cadastrar, consultar, editar e excluir serviços com duração e preço.
- RF07: cadastrar agendamento relacionando cliente, serviço e barbeiro previamente cadastrados.
- RF08: listar agendamentos ordenados por data e horário com dados do cliente, serviço e barbeiro.
- RF09: impedir sobreposição de atendimentos para o mesmo barbeiro.
- RF10: atualizar o status do agendamento para concluído ou cancelado.

## Requisitos não funcionais e segurança

- RNF01: armazenar CPF com criptografia autenticada AES-256-GCM; o índice de unicidade usa HMAC-SHA-256.
- RNF02: armazenar senhas com scrypt e comparação em tempo constante; senhas não são reversivelmente criptografadas.
- RNF03: proteger o identificador de sessão em cookie HttpOnly, SameSite=Strict, com validade de 30 minutos.
- RNF04: usar chaves estrangeiras, restrições de domínio e índices no SQLite.
- RNF05: não retornar CPF completo pela API; a interface recebe apenas uma versão mascarada.

## Modelo de dados

O diagrama entidade-relacionamento está em [docs/DER.png](docs/DER.png), com a fonte vetorial em [docs/DER.svg](docs/DER.svg). O script [saep_db.sql](saep_db.sql) cria as cinco tabelas e inclui três registros iniciais em cada uma.

| Entidade | Campos principais |
| --- | --- |
| usuarios | id, name, username, password_hash |
| clientes | id, name, phone, email, CPF criptografado e hash de busca |
| barbeiros | id, name, phone, specialty, CPF criptografado e hash de busca |
| servicos | id, name, duration, price |
| agendamentos | id, client_id, barber_id, service_id, starts_at, status, notes |

Relacionamentos: clientes 1:N agendamentos; barbeiros 1:N agendamentos; servicos 1:N agendamentos.

## Como executar

Requer Node.js 22.5 ou superior. A aplicação usa o módulo SQLite nativo do Node, sem dependências npm externas.

```powershell
npm start
```

Acesse http://localhost:3001. A base `data/barbearia.db` é criada automaticamente usando `saep_db.sql`.

Credenciais demonstrativas: usuário `admin`, senha `Admin123!`.

Para produção, defina `DATA_ENCRYPTION_KEY` com um segredo forte e exclusivo e `NODE_ENV=production`. A chave deve ser mantida estável e protegida; alterá-la sem recriptografar os CPFs impede a leitura dos dados existentes. As credenciais e a chave padrão destinam-se somente à demonstração local.

## Verificação

```powershell
npm run check
```