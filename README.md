# Digital Signature with JavaScript
[Demo](https://giselesousar.github.io/digital-signature-js/)
# Introdução

Este trabalho tem como objetivo desenvolver um sistema de criação e verificação de assinaturas digitais. 
- Através do uso de algoritmos assimétricos, o sistema gera uma chave privada e um certificado auto-assinado. 
- Em posse da chave privada, é possível assinar um determinado arquivo escolhido. 
- É possível verificar se uma determinada assinatura é válida ao informar o arquivo original, o arquivo assinado e o certificado digital. 

Durante cada uma dessas fases, a interface possibilita a escolha de alguns parâmetros necessários para a realização das operações. Para o desenvolvimento da aplicação, utilizou-se a biblioteca [node-forge](https://npm.io/package/node-forge) do [NodeJS](https://nodejs.org/en/download/).

# Pré-requisitos

Nesta seção temos as instruções necessárias para instalação das ferramentas utilizadas no desenvolvimento da aplicação. Aqui temos todos os pré-requisitos exigidos para que a aplicação funcione corretamente.

## NodeJs e NPM

O primeiro passo é instalar o Node.js, que vem acompanhado do NPM. A seguir temos um passo a passo para a instalação nos sistemas operacionais mais utilizados.

#### MacOS

Para o macOS iremos utilizar o gerenciador de pacotes [**Homebrew**](https://brew.sh/index_pt-br), que é instalado usando Ruby, que já vem instalado por padrão, execute o seguinte comando no terminal:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

Para verificar se ele foi instalado com sucesso execute:

```bash
brew --version
```

Com o **Homebrew** instalado, basta executar o comando para instalar a versão 14 (LTS) mais recente:

```bash
brew install node@14
```

Como instalamos uma versão do Node diferente da default do Homebrew (o padrão é a current, nesse caso v15), é preciso adicionar manualmente o `path` do Node na nossa variável ambiente. Adicione a seguinte linha ao final do arquivo `~/.bashrc` (ou do arquivo `~/.zshrc` caso você utilize o shell ZSH):

```bash
export PATH="/usr/local/opt/node@14/bin:$PATH"
```

Por fim, reinicie o terminal e execute os seguintes comandos:

```bash
node -v
npm -v
```

Caso retorne as versões do Node e Npm, sua instalação foi um sucesso.

#### Linux (Ubuntu/Debian)

Para o Linux iremos utilizar o **[NodeSource](https://github.com/nodesource/distributions/blob/master/README.md)**, basta seguir esses passos:

- Verifique se você possui o **[curl](https://curl.haxx.se/)** instalado rodando no terminal o comando:

```bash
curl --version
```

Caso ele retorne a versão, pode pular para o próximo passo. Caso não, basta rodar o comando:

```bash
sudo apt install curl
```

- Com o **curl** instalado, execute o comando de instalação da versão LTS mais recente disponível:
    - Ubuntu

    ```bash
    curl -sL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    sudo apt-get install -y nodejs
    ```

    - Debian (como root)

    ```json
    curl -sL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y nodejs
    ```

    Feche o terminal e abra novamente para as alterações fazerem efeito.

- Por fim, execute os seguintes comandos no terminal:

```bash
node -v
npm -v
```

Caso retorne as versões do Node e npm, sua instalação foi um sucesso.

#### Windows

Para o Windows utilizaremos o gerenciador de pacotes **[Chocolatey](https://chocolatey.org/)**, porém antes dos passos de instalação vamos falar brevemente sobre qual shell você deve usar.

- **CMD**: também conhecido como **Command Prompt**, ele é um dos shells mais antigos da atualidade (foi construído para ser compatível com o **MS-DOS**) e, apesar da sua fama, hoje em dia tem sido cada vez menos utilizado.
- **Powershell**: novo shell apresentado pela Microsoft por volta de 2005, ele apresenta diversas melhorias em relação ao **CMD**, tornando-o popular atualmente.

Escolhido o shell, vamos começar a instalação:

- Busque no campo de busca do Windows por **Windows Powershell**, clique com o botão direito em cima do programa e escolha a opção **Executar como administrador**.
- O Powershell trabalha com um esquema de autorizações (conhecido como `Execution Policy`) para execução de scripts e, por isso, precisamos verificar se o presente no sistema está compatível com o que o Chocolatey precisa. Execute o seguinte comando:

```bash
Get-ExecutionPolicy
```

Caso ele retorne `Restricted`, execute o comando:

```bash
Set-ExecutionPolicy RemoteSigned
```

E escolha a opção `[A] Sim para Todos`

Caso o comando acima apresente erro, tente usar:

`Set-ExecutionPolicy Bypass -Scope Process`

Verifique se alteração de permissão ocorreu com sucesso executando novamente o comando:

```bash
Get-ExecutionPolicy
```

Alterada a permissão, basta instalar o **Chocolatey** com o comando:

```bash
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

Caso o comando acima apresente um erro, verifique se a sua máquina atende às requisições mínimas

`Windows 7+ / Windows Server 2003+
PowerShell v3+
.NET Framework 4.5+`

Caso o erro apresentado seja `Exceção ao definir "SecurityProtocol": "Não é possível converter o valor "3312"`, siga **[esse guia](https://blog.chocolatey.org/2020/01/remove-support-for-old-tls-versions/).**

- Após o fim da instalação, feche e abra o powershell como administrador novamente e execute:

```bash
choco -v
```

Caso ele retorne a versão do **Chocolatey**, a instalação foi um sucesso. Para finalizar, basta instalar a versão LTS mais recente do Node com o seguinte comando:

```bash
cinst nodejs-lts
```

E escolha a opção `[A]ll - yes to all`

Após o fim da instalação, feche e abra o powershell como administrador novamente e execute:

```bash
node -v
npm -v
```

Caso retorne as versões do Node e npm, sua instalação foi um sucesso.

# Como usar

Uma vez tendo o NodeJS instalado na sua máquina, basta acessar o diretório que contém o código fonte da aplicação e executar os seguintes comandos no terminal ou no prompt de comando: 

- `npm i`

Esse comando instalará todas as dependências necessárias.

- `npm run serve`

Esse comando iniciará a aplicação. Para utilizá-la, acesse [localhost:8080](http://localhost:8080).