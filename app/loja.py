"""Loja de exemplo: servidor HTTP mínimo usado como artefato do pipeline.

Só usa a biblioteca padrão. Rotas:
  GET /       -> página da loja (JSON com a mensagem e a versão)
  GET /saude  -> {"status": "ok"} (liveness/readiness no Kubernetes)

Variáveis de ambiente:
  LOJA_PORTA     porta TCP (padrão 8080)
  LOJA_MENSAGEM  mensagem exibida em / (o workflow de ataques troca este valor
                 na imagem adulterada, o que deixa a diferença visível no cluster)
  LOJA_VERSAO    commit que gerou a imagem (definido no build)
"""

import json
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MENSAGEM_PADRAO = "Bem-vindo à loja de exemplo (imagem legítima do pipeline)"

PRODUTOS = [
    {"id": 1, "nome": "Caneca UFSC", "preco": 25.0},
    {"id": 2, "nome": "Camiseta Sigstore", "preco": 60.0},
    {"id": 3, "nome": "Adesivo Merkle", "preco": 5.0},
]


class Manipulador(BaseHTTPRequestHandler):
    server_version = "loja/1.0"

    def version_string(self):
        # Não expõe a versão do Python no cabeçalho Server.
        return self.server_version

    def _responder(self, status, corpo):
        dados = json.dumps(corpo, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(dados)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(dados)

    def do_GET(self):  # noqa: N802 (nome exigido pelo http.server)
        caminho = self.path.split("?", 1)[0]
        if caminho == "/":
            self._responder(
                200,
                {
                    "loja": "sigstore-supply-chain",
                    "mensagem": os.environ.get("LOJA_MENSAGEM", MENSAGEM_PADRAO),
                    "versao": os.environ.get("LOJA_VERSAO", "desconhecida"),
                    "produtos": PRODUTOS,
                },
            )
        elif caminho == "/saude":
            self._responder(200, {"status": "ok"})
        else:
            self._responder(404, {"erro": "rota não encontrada"})

    def log_message(self, formato, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), formato % args))


def main():
    porta = int(os.environ.get("LOJA_PORTA", "8080"))
    # Escuta em todas as interfaces porque roda dentro do container/pod.
    endereco = os.environ.get("LOJA_ENDERECO", "0.0.0.0")
    servidor = ThreadingHTTPServer((endereco, porta), Manipulador)

    def encerrar(_sinal, _quadro):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, encerrar)
    print(f"loja ouvindo em {endereco}:{porta}", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()


if __name__ == "__main__":
    main()
