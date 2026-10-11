import os
import json
import bcrypt
import mysql.connector
from mysql.connector import Error
from pymongo import MongoClient
from pymongo.errors import WriteError, OperationFailure
from dotenv import load_dotenv

# ==========================================
# PREPARAÇÃO E CONEXÕES
# ==========================================
load_dotenv()

def conectar_mysql():
    try:
        # 1. Conecta apenas ao servidor MySQL, omitindo o parâmetro 'database'
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD")
        )
        if conn.is_connected():
            print("[OK] Conectado ao servidor MySQL com sucesso.")
            
            cursor = conn.cursor()
            nome_banco = os.getenv("MYSQL_DATABASE")
            
            # 2. Cria o banco de dados se ele ainda não existir
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {nome_banco}")
            
            # 3. Seleciona o banco para as próximas operações
            cursor.execute(f"USE {nome_banco}")
            
            # 4. Setup inicial da tabela de ativos
            cursor.execute("DROP TABLE IF EXISTS ativos") 
            
            cursor.execute("""
                CREATE TABLE ativos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    nome_ativo VARCHAR(100) UNIQUE,
                    tipo VARCHAR(50),
                    ip_interno VARCHAR(20),
                    setor_responsavel VARCHAR(50),
                    sistema_operacional VARCHAR(100),
                    data_ultima_verificacao DATE,
                    status_patch VARCHAR(20),
                    senha_acesso_hash VARCHAR(255)
                )
            """)
            conn.commit()
            return conn
    except Error as e:
        print(f"[ERRO] Falha ao conectar no MySQL: {e}")
        return None

def conectar_mongodb():
    try:
        client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client[os.getenv("MONGO_DB")]
        print("[OK] Conectado ao MongoDB com sucesso.")
        return db
    except Exception as e:
        print(f"[ERRO] Falha ao conectar no MongoDB: {e}")
        return None

# ==========================================
# CRUD EM ATIVOS COM SEGURANÇA (MySQL)
# ==========================================
def cadastrar_ativo(conn, nome, tipo, ip, setor, so, data, status, senha_texto_puro):
    # SEGURANÇA: Geração de Hash com Salt usando bcrypt
    salt = bcrypt.gensalt()
    hash_senha = bcrypt.hashpw(senha_texto_puro.encode('utf-8'), salt).decode('utf-8')
    
    cursor = conn.cursor()
    query = """INSERT INTO ativos (nome_ativo, tipo, ip_interno, setor_responsavel, sistema_operacional, data_ultima_verificacao, status_patch, senha_acesso_hash) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
    try:
        cursor.execute(query, (nome, tipo, ip, setor, so, data, status, hash_senha))
        conn.commit()
        print(f"Ativo '{nome}' cadastrado com sucesso (Senha protegida por Hash).")
    except Error as e:
        print(f"Erro ao cadastrar ativo: {e}")

def verificar_senha_ativo(conn, nome_ativo, senha_tentativa):
    print(f"\n--- TENTATIVA DE LOGIN: {nome_ativo} ---")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT senha_acesso_hash FROM ativos WHERE nome_ativo = %s", (nome_ativo,))
    resultado = cursor.fetchone()
    
    if resultado:
        hash_salvo = resultado['senha_acesso_hash']
        # Compara a senha informada com o hash armazenado
        if bcrypt.checkpw(senha_tentativa.encode('utf-8'), hash_salvo.encode('utf-8')):
            print("[SUCESSO] Senha correta! Acesso administrativo liberado.")
            return True
        else:
            print("[FALHA] Senha incorreta! Acesso negado.")
            return False
    print("[FALHA] Ativo não encontrado.")
    return False

def buscar_ativo_por_setor(conn, setor):
    """
    ===============================================================
    PREVENÇÃO DE SQL INJECTION: EXEMPLO COMPARATIVO
    ===============================================================
    
    VULNERÁVEL (Concatenação de Strings):
    query_vulneravel = f"SELECT * FROM ativos WHERE setor_responsavel = '{setor}'"
    cursor.execute(query_vulneravel)
    
    Por que é vulnerável? 
    Se a variável 'setor' recebesse o valor: TI' OR '1'='1
    A query montada seria: SELECT * FROM ativos WHERE setor_responsavel = 'TI' OR '1'='1'
    Isso forçaria o banco a retornar TODOS os ativos da empresa, ignorando o filtro de setor,
    vazando dados sigilosos.
    
    SEGURO (Prepared Statements):
    Ao utilizar '%s' e passar a variável como uma tupla (setor,), o driver do MySQL
    (mysql-connector) aplica um escape automático, tratando "' OR '1'='1" como um 
    texto literal e inofensivo, buscando exatamente um setor com esse nome bizarro (e não encontrando nada).
    ===============================================================
    """
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM ativos WHERE setor_responsavel = %s", (setor,))
    return cursor.fetchall()

# ==========================================
# SEGURANÇA E VALIDAÇÃO NO MONGODB
# ==========================================
def aplicar_validacao_esquema_mongodb(db):
    esquema = {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["ativo_relacionado", "categoria", "severidade", "score_cvss"],
            "properties": {
                "categoria": {
                    "enum": ["sistema_operacional", "rede", "aplicacao_web", "endpoint"],
                    "description": "Deve ser estritamente uma das categorias predefinidas"
                },
                "score_cvss": {
                    "bsonType": ["double", "int"],
                    "description": "O score CVSS deve ser um valor numérico"
                }
            }
        }
    }
    
    try:
        db.command("collMod", "vulnerabilidades", validator=esquema)
    except OperationFailure:
        db.create_collection("vulnerabilidades", validator=esquema)
    print("Validação de esquema ($jsonSchema) aplicada na coleção 'vulnerabilidades'.")

def testar_rejeicao_mongodb(db):
    print("\n--- TESTANDO VALIDAÇÃO DE ESQUEMA (MONGODB) ---")
    doc_invalido = {
        "ativo_relacionado": "srv-teste-01",
        "categoria": "engenharia_social", # INVÁLIDO: Fora do enum permitido
        "severidade": "critica",
        "score_cvss": "dez" # INVÁLIDO: String ao invés de numérico (double/int)
    }
    
    try:
        db.vulnerabilidades.insert_one(doc_invalido)
        print("[ALERTA] O documento inválido foi inserido! O esquema falhou.")
    except WriteError as e:
        print("[SUCESSO] Inserção bloqueada pelo MongoDB.")
        print(f"Motivo técnico da rejeição: {e.details.get('errInfo', {}).get('details', e)}")

def carregar_dataset(db, arquivo_json='vulnerabilidades.json'):
    colecao = db.vulnerabilidades
    colecao.delete_many({}) 
    with open(arquivo_json, 'r') as f:
        dados = json.load(f)
        colecao.insert_many(dados)
    print(f"Dataset '{arquivo_json}' carregado com sucesso.")

# ==========================================
# EXECUÇÃO DO FLUXO COMPLETO
# ==========================================
if __name__ == "__main__":
    mysql_conn = conectar_mysql()
    mongo_db = conectar_mongodb()

    if mysql_conn is not None and mongo_db is not None:
        
        # Etapa de Segurança MongoDB
        aplicar_validacao_esquema_mongodb(mongo_db)
        testar_rejeicao_mongodb(mongo_db)
        
        print("\n--- TESTANDO CRUD SEGURO NO MYSQL ---")
        # Inserindo ativos com senhas puras que serão hasheadas
        cadastrar_ativo(mysql_conn, "srv-web-01", "servidor", "192.168.1.10", "TI", "Linux", "2026-09-01", "em_dia", "Senha@Forte123")
        
        # Testando autenticação
        verificar_senha_ativo(mysql_conn, "srv-web-01", "Senha@Fraca") # Deve falhar
        verificar_senha_ativo(mysql_conn, "srv-web-01", "Senha@Forte123") # Deve passar
        
        # Demonstrando funcionamento do Prepared Statement
        print("\nBusca segura de ativos pelo setor 'TI':")
        ativos_ti = buscar_ativo_por_setor(mysql_conn, "TI")
        for ativo in ativos_ti:
            print(f"- {ativo['nome_ativo']} (Hash armazenado: {ativo['senha_acesso_hash'][:20]}...)")
        
        # Carga dos dados para não quebrar a lógica original
        carregar_dataset(mongo_db)

        mysql_conn.close()