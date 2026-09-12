import asyncio
import re
import time
import signal
import sys
from collections import defaultdict

# =====================================================================
# 1. MODULE COMPILATION : LEXER, PARSER & AST (Engine DSL Sécurité)
# =====================================================================

class TokenType:
    FIELD = "FIELD"       # uri, method, req_count
    OPERATOR = "OPERATOR" # EQUALS, CONTAINS, GT
    VALUE = "VALUE"       # 'admin', 5
    AND = "AND"
    THEN = "THEN"
    ACTION = "ACTION"     # BLOCK, ALLOW

class Token:
    def __init__(self, type_, value):
        self.type = type_
        self.value = value

    def __repr__(self):
        return f"Token({self.type}, '{self.value}')"

class SecurityRuleLexer:
    """ Analyseur Lexical : Transforme la règle textuelle en suite de Tokens """
    def __init__(self, rule_text):
        self.text = rule_text

    def tokenize(self):
        tokens = []
        words = self.text.split()
        for w in words:
            if w in ["uri", "method", "req_count"]:
                tokens.append(Token(TokenType.FIELD, w))
            elif w in ["CONTAINS", "EQUALS", ">"]:
                tokens.append(Token(TokenType.OPERATOR, w))
            elif w == "AND":
                tokens.append(Token(TokenType.AND, w))
            elif w == "THEN":
                tokens.append(Token(TokenType.THEN, w))
            elif w in ["BLOCK", "ALLOW"]:
                tokens.append(Token(TokenType.ACTION, w))
            else:
                tokens.append(Token(TokenType.VALUE, w.strip("'\"")))
        return tokens

class ASTNode:
    """ Noeud d'Arbre de Syntaxe Abstraite (AST) """
    def __init__(self, field, operator, value):
        self.field = field
        self.operator = operator
        self.value = value

    def evaluate(self, context):
        val_ctx = context.get(self.field)
        if self.operator == "CONTAINS":
            return str(self.value).lower() in str(val_ctx).lower()
        elif self.operator == "EQUALS":
            return str(val_ctx).lower() == str(self.value).lower()
        elif self.operator == ">":
            return float(val_ctx) > float(self.value)
        return False

class RuleCompiler:
    """ Compilateur : Compile la règle DSL en Arbre d'Exécution AST """
    def __init__(self, rule_text):
        self.lexer = SecurityRuleLexer(rule_text)
        self.ast_nodes = []
        self.action = "ALLOW"
        self._compile()

    def _compile(self):
        tokens = self.lexer.tokenize()
        i = 0
        while i < len(tokens):
            if tokens[i].type == TokenType.FIELD:
                field = tokens[i].value
                op = tokens[i+1].value
                val = tokens[i+2].value
                self.ast_nodes.append(ASTNode(field, op, val))
                i += 3
            elif tokens[i].type == TokenType.THEN:
                self.action = tokens[i+1].value
                break
            else:
                i += 1

    def execute(self, request_context):
        """ Exécute l'AST compilé sur le contexte réseau courant """
        for node in self.ast_nodes:
            if not node.evaluate(request_context):
                return "ALLOW"  # Si une condition n'est pas remplie, on ne bloque pas
        return self.action

# Exemple de règle compilée au démarrage
REGLE_DSL = "uri CONTAINS 'select' THEN BLOCK"
COMPILER_ENGINE = RuleCompiler(REGLE_DSL)

# =====================================================================
# 2. MODULE OS & RÉSEAU : PROXY ASYNCHRONE & SIGNAUX SYSTÈME
# =====================================================================

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
BACKEND_SERVERS = [("127.0.0.1", 9001), ("127.0.0.1", 9002)]
backend_index = 0

RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW = 10
ip_history = defaultdict(list)

def verifier_rate_limit(client_ip):
    maintenant = time.time()
    ip_history[client_ip] = [t for t in ip_history[client_ip] if maintenant - t < RATE_LIMIT_WINDOW]
    if len(ip_history[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    ip_history[client_ip].append(maintenant)
    return True

def extraire_contexte_http(raw_req, client_ip):
    """ Parseur HTTP (Module Réseau) """
    req_text = raw_req.decode('utf-8', errors='ignore')
    lines = req_text.split("\r\n")
    first_line = lines[0] if lines else ""
    parts = first_line.split(" ")
    
    method = parts[0] if len(parts) > 0 else "GET"
    uri = parts[1] if len(parts) > 1 else "/"
    
    return {
        "uri": uri,
        "method": method,
        "req_count": len(ip_history[client_ip]),
        "client_ip": client_ip
    }

async def relayer_donnees(reader, writer):
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass

async def handle_client(reader_client, writer_client):
    global backend_index
    client_ip, _ = writer_client.get_extra_info('peername')

    # 1. Contrôle OS / Réseau Rate Limiting
    if not verifier_rate_limit(client_ip):
        print(f"🚨 [OS/ANTI-DDOS] Seuil dépassé pour l'IP {client_ip}")
        writer_client.write(b"HTTP/1.1 429 Too Many Requests\r\n\r\n429 Rate Limit Exceeded\n")
        await writer_client.drain()
        writer_client.close()
        return

    raw_req = await reader_client.read(4096)
    if not raw_req:
        writer_client.close()
        return

    # 2. Module Compilation / Sec : Évaluation de l'AST compilé
    context = extraire_contexte_http(raw_req, client_ip)
    decision = COMPILER_ENGINE.execute(context)

    if decision == "BLOCK":
        print(f"🛡️ [WAF COMPILER] Requête bloquée par l'AST ! (URI: {context['uri']})")
        writer_client.write(b"HTTP/1.1 403 Forbidden\r\n\r\n403 Blocked by Compiled Rule Engine\n")
        await writer_client.drain()
        writer_client.close()
        return

    # 3. Réseau : Load Balancing Round-Robin
    b_host, b_port = BACKEND_SERVERS[backend_index]
    backend_index = (backend_index + 1) % len(BACKEND_SERVERS)
    print(f"🔀 [ROUTAGE TCP] Client {client_ip} -> Backend {b_host}:{b_port}")

    try:
        r_back, w_back = await asyncio.open_connection(b_host, b_port)
        w_back.write(raw_req)
        await w_back.drain()

        t1 = asyncio.create_task(relayer_donnees(reader_client, w_back))
        t2 = asyncio.create_task(relayer_donnees(r_back, writer_client))
        await asyncio.gather(t1, t2)
    except Exception as e:
        writer_client.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n502 Bad Gateway\n")
        await writer_client.drain()
    finally:
        writer_client.close()

# =====================================================================
# 3. GESTION DES SIGNAUX OS (Graceful Shutdown)
# =====================================================================

def installer_gestionnaires_signaux_os(server):
    """ Capture des signaux Linux/OS pour un arrêt propre """
    def shutdown_handler():
        print("\n🛑 [OS SIGNAL] Signal d'arrêt reçu (SIGINT/SIGTERM). Fermeture des sockets...")
        server.close()
        sys.exit(0)
    
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_handler)
    except NotImplementedError:
        pass # Windows OS fallback

async def main():
    server = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    installer_gestionnaires_signaux_os(server)

    print("=================================================================")
    print(f"🚀 ENGINE SYSTEME / COMPILATEUR / WAF DÉMARRÉ SUR {PROXY_HOST}:{PROXY_PORT}")
    print(f"📜 Règle DSL Compilée en AST : \"{REGLE_DSL}\"")
    print("=================================================================")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass