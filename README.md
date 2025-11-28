# BIP39 Recovery Tool - BIP44 CUSTOM INDEX v1.0.0


## Requisitos
  -  [Go][install-go]
  -  [Git][install-git]
  -  Terminal

# Instruções para rodar o projeto no Windows.

 * Clona o repo e brota na pasta:
```bash
git clone https://github.com/foxlife281/Recovery_Tool.git && cd Recovery_Tool
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

 * Clona o repo e brota na pasta:
```bash
  git clone https://github.com/foxlife281/Recovery_Tool.git && cd Recovery_Tool
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

[install-go]: https://go.dev/doc/install
[install-git]: https://git-scm.com/download/win
