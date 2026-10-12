# Gestão Segura de Ativos e Vulnerabilidades (DevSecOps)

Este projeto é um sistema híbrido de DevSecOps desenvolvido em Python que gerencia o inventário de ativos de TI e monitora vulnerabilidades de segurança. O sistema resolve o desafio de integrar dados estruturados de infraestrutura com registros dinâmicos de auditoria, implementando defesas ativas diretamente no código.

## 🚀 Tecnologias Utilizadas
* **Linguagem:** Python 3
* **Bancos de Dados:** MySQL (Relacional) e MongoDB (NoSQL)
* **Segurança:** Criptografia Bcrypt
* **Bibliotecas:** `mysql-connector-python`, `pymongo`, `python-dotenv`, `bcrypt`

## 🛡️ Funcionalidades de Segurança Implementadas
O código foi concebido com foco em boas práticas de segurança defensiva:
* **Prevenção contra SQL Injection:** Utilização estrita de *Prepared Statements* em todas as consultas ao MySQL, impossibilitando a manipulação de *inputs* maliciosos.
* **Proteção de Credenciais:** As senhas de acesso aos equipamentos nunca são armazenadas em texto limpo. Foi implementada uma função de *hash* com *salt* (Bcrypt) para mitigar riscos em caso de vazamento de dados.
* **Validação Rigorosa de Esquemas (NoSQL):** Aplicação de regras `$jsonSchema` no MongoDB, forçando a tipagem correta e o uso de *enums*, evitando a corrupção do banco de dados e injeções NoSQL.
* **Quarentena Automática:** Rotina que isola equipamentos no inventário (alterando o status para "crítico") caso o MongoDB registre uma vulnerabilidade ativa com pontuação CVSS superior a 9.0.

## ⚙️ Como Executar o Projeto

1. Clone o repositório:
   ```bash
   git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
   ```
2. Instale as dependências:
   ```bash
   pip install mysql-connector-python pymongo python-dotenv bcrypt
   ```
3. Renomeie o arquivo `.env.example` para `.env` e insira as suas credenciais locais do MySQL e MongoDB.
4. Execute a aplicação:
   ```bash
   python main.py
   ```

## 👨‍💻 Autor
**Victor Henrique de Barros Oliveira**