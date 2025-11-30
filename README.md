# BIP39 Recovery Tool - BIP44 CUSTOM INDEX v1.0.0


## Requisitos
  -  [Go][install-go]
  -  [Git][install-git]
  -  Terminal

# Instruções para rodar o projeto no Windows.

 * Clona o repo e entra na pasta:
```bash
git clone https://github.com/fox01010010/fox_crypto.git && cd Recovery_Tool
```
 
 * Instala as parada:
```bash
go mod tidy
```

 * Faz o build do projeto:
```bash
go build -o recovery.exe ./main.go
```

 * Executa o que foi compilado:
```bash
go.bat
```

* Executar sem compilar:
```bash
go_1.bat
```


# Instruções para rodar o projeto no Linux / MacOS.

 * Clona o repo e entra na pasta:
```bash
  git clone https://github.com/fox01010010/fox_crypto.git && cd Recovery_Tool
```

 * Instala as parada:
```bash
 go mod tidy
```

 * Faz o build do projeto:
```bash
go build -o recovery ./main.go
```

 * Executa o que foi compilado:
```bash
./recovery
```
* Rodar Direto sem compilar:
```bash
chmod +x go.sh
```
* Agora rode o comando:
```bash
./go.sh
```
* Teste Executado:
```bash
🌍 SELECIONE O IDIOMA DO DICIONÁRIO BIP39:
a - English
b - Portuguese
c - Japanese
d - Korean
e - Spanish
f - Chinese (Simplified)
g - Chinese (Traditional)
h - French
i - Italian
j - Czech

👉 Digite a letra do idioma desejado: a
✅ Idioma selecionado: English
✅ Dicionário carregado: English (2048 palavras)

                                               
                  ____ ___ _____ ____ ___ ___ _   _ 
                 | __ )_ _|_   _/ ___/ _ \_ _| \ | |
                 |  _ \| |  | || |  | | | | ||  \| |
                 | |_) | |  | || |__| |_| | || |\  |
                 |____/___| |_| \____\___/___|_| \_|
                                    

                BIP39 Recovery Tool - BIP44 CUSTOM INDEX

=== Bitcoin Address Recovery Tool ===

👉 Digite o endereço alvo BIP44 (1...): 19iRjyeGSW6hqMawQpELHCchwwM2EVoHYk
👉 Digite suas palavras (12, 15, 18, 21 ou 24) separadas por espaço: puzzle stove pepper laugh before deal shrimp dash mean toy poverty team
🔐 Digite a passphrase (Enter para nenhuma): 
🔢 Digite o índice do endereço para testar (0, 1, 2, ...): 0
🧠 Núcleos disponíveis: 24
🔧 Quantos núcleos usar (1-24, Enter para todos)? 24
🔁 Continuar de onde parou? (s/n): n

==================================================
🚀 INICIANDO BUSCA...
==================================================

🔍 TESTE DIRETO BIP44:
Frase: puzzle stove pepper laugh before deal shrimp dash mean toy poverty team
Alvo:  19iRjyeGSW6hqMawQpELHCchwwM2EVoHYk
Índice: 0
Caminho: m/44'/0'/0'/0/0
Número de palavras: 12
Endereço gerado: 1rds4PzS7a3J3CLouQBRv1FZU23ncgQ9d
❌ Frase incorreta - iniciando permutações...

✅ 12 palavras válidas. Iniciando busca BIP44...
🔍 Alvo: 19iRjyeGSW6hqMawQpELHCchwwM2EVoHYk
🔐 Passphrase: ''
📍 Derivação: m/44'/0'/0'/0/0
📊 Total de permutações: 479001600
🎯 Palavras prioritárias: [puzzle stove deal shrimp team]
🧠 Estratégia: Prioridade
⚙️ Usando 24 núcleo(s)

----- 🎉 ENCONTRADO! -----
📝 Mnemonic: puzzle stove pepper laugh before mean toy poverty team deal shrimp dash
🎯 Endereço: 19iRjyeGSW6hqMawQpELHCchwwM2EVoHYk
🔐 Passphrase: 
🔑 WIF: L1qWxaAHorqWKWapZuu4dJ6Ls2T4wBSTnt7Vfyz4WxXxKwQJ6VyD
📍 Derivação: m/44'/0'/0'/0/0
📊 Índice usado: 0
🔢 Número de palavras: 12
✅ Dados salvos em 'found.txt'
```

[install-go]: https://go.dev/doc/install
[install-git]: https://git-scm.com/download/win
