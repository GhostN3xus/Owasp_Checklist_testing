#!/usr/bin/env python3
"""
Servidor simples para servir a aplicação OWASP Checklist Platform
Acesse em http://localhost:8000
"""

import http.server
import socketserver
import os
from pathlib import Path

PORT = 8000
HANDLER = http.server.SimpleHTTPRequestHandler

def run_server():
    # Muda para o diretório raiz do projeto
    os.chdir(Path(__file__).parent)

    with socketserver.TCPServer(("", PORT), HANDLER) as httpd:
        print(f"🚀 Servidor rodando em http://localhost:{PORT}")
        print(f"📁 Servindo arquivos de: {os.getcwd()}")
        print(f"✨ Pressione Ctrl+C para parar o servidor")
        print()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Servidor parado")

if __name__ == "__main__":
    run_server()
