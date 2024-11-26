/* 
DISCENTES: 
Fabyani Tiva Yan (RA: 10431835) 
Rute Willemann (RA: 10436781)

RODAR O CÓDIGO NO TERMINAL:
gcc -o projeto 1-projeto-codificacao.c -lssl -lcrypto
./projeto

*/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdint.h>

#define MAX_TAMANHO 128
#define MAX_SENHAS 1000
#define TAM_PALAVRAS 12
#define QTD_PALAVRAS 15

// Função para codificar Base64
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = strndup(bufferPtr->data, bufferPtr->length); 
    return 0;
}

// Função para carregar senhas codificadas de um arquivo
int carregarSenhasCodificadas(char *senhas_codificadas[MAX_SENHAS]) {
    FILE *arquivo = fopen("/workspaces/apii-projeto2/usuarios_senhascodificadas.txt", "r");
    if (arquivo == NULL) {
        printf("\nERRO ao abrir o arquivo 'usuarios_senhascodificadas.txt'!\n");
        return 0;
    }

    int qtd_senhas = 0;
    while (!feof(arquivo) && qtd_senhas < MAX_SENHAS) {
        senhas_codificadas[qtd_senhas] = malloc(MAX_TAMANHO * sizeof(char));
        if (senhas_codificadas[qtd_senhas] == NULL) {
            printf("Erro ao alocar memória para senha codificada.\n");
            fclose(arquivo);
            return -1;
        }
        fgets(senhas_codificadas[qtd_senhas], MAX_TAMANHO, arquivo);
        senhas_codificadas[qtd_senhas][strcspn(senhas_codificadas[qtd_senhas], "\n")] = '\0';
        qtd_senhas++;
    }

    fclose(arquivo);
    return qtd_senhas;
}

// Função para carregar palavras de um arquivo
int carregarPalavras(char palavras[QTD_PALAVRAS][TAM_PALAVRAS]) {
    FILE *arquivo = fopen("/workspaces/apii-projeto2/palavras.txt", "r");
    if (arquivo == NULL) {
        printf("\nERRO ao abrir o arquivo 'palavras.txt'!\n");
        return 0;
    }

    int qtd_palavras = 0;
    while (!feof(arquivo) && qtd_palavras < QTD_PALAVRAS) {
        fgets(palavras[qtd_palavras], TAM_PALAVRAS, arquivo);
        palavras[qtd_palavras][strcspn(palavras[qtd_palavras], "\n")] = '\0';
        qtd_palavras++;
    }

    fclose(arquivo);
    return qtd_palavras;
}

// Função para codificar uma senha usando SHA-512
char *codificar_senha(const char *senha) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;

    SHA512_Init(&sha512);
    SHA512_Update(&sha512, senha, strlen(senha));
    SHA512_Final(hash, &sha512);

    char *encoded;
    Base64Encode(hash, SHA512_DIGEST_LENGTH, &encoded);
    return encoded;
}

// Função para salvar a combinação no arquivo
void salvar_combinacao(const char *senha_original, const char *nome_usuario, const char *senha_codificada) {
    FILE *arquivo = fopen("/workspaces/apii-projeto2/senhas_combinacoes.txt", "a");
    if (arquivo == NULL) {
        printf("\nERRO ao abrir o arquivo 'senhas_combinacoes.txt' para escrita!\n");
        return;
    }

    if (nome_usuario != NULL) {
        fprintf(arquivo, "Senha: %s | Usuário: %s | Codificada: %s\n", senha_original, nome_usuario, senha_codificada);
    } else {
        fprintf(arquivo, "Senha: %s | Usuário: Não descoberto | Codificada: %s\n", senha_original, senha_codificada);
    }

    fclose(arquivo);
    printf("\nA combinação foi salva em 'senhas_combinacoes.txt'.\n");
}

int main() {
    char *senhas_codificadas[MAX_SENHAS];
    char palavras[QTD_PALAVRAS][TAM_PALAVRAS];


    ///// Carregar senhas codificadas do arquivo /////
    int qtd_senhas = carregarSenhasCodificadas(senhas_codificadas);
    if (qtd_senhas == 0) {
        printf("Nenhuma senha carregada do arquivo 'usuarios_senhascodificadas.txt'.\n");
    }


    ///// Carregar palavras do arquivo /////
    int qtd_palavras = carregarPalavras(palavras);
    if (qtd_palavras == 0) {
        printf("Nenhuma palavra carregada do arquivo 'palavras.txt'.\n");
    }


    ///// Solicitar combinação /////
    char senha_usuario[MAX_TAMANHO * 5];
    printf("\nDigite a senha ou combinação de palavras que deseja codificar: ");
    fgets(senha_usuario, sizeof(senha_usuario), stdin);
    senha_usuario[strcspn(senha_usuario, "\n")] = '\0'; // Remover newline


    ///// Codificação /////
    char *senha_codificada = codificar_senha(senha_usuario);
    printf("Senha codificada: %s\n", senha_codificada);


    ///// Solicitar verificação manual ao usuário /////
    printf("\n\n----- VERIFICAÇÃO DE SENHA -----\n");
    printf("1) COPIE A SENHA CODIFICADA\n");
    printf("2) ABRA O ARQUIVO 'usuarios_senhascodificadas.txt'\n");
    printf("3) DIGITE O COMANDO Ctrl+F\n");
    printf("4) COLE A SENHA CODIFICADA\n");
    printf("\n\nA senha codificada existe no arquivo? (S/N): ");

    char resposta;
    scanf(" %c", &resposta);

    if (resposta == 's' || resposta == 'S') {
        char nome_usuario[MAX_TAMANHO];
        printf("\nDigite o nome do usuário relacionado à senha: ");
        scanf(" %127s", nome_usuario); 
        salvar_combinacao(senha_usuario, nome_usuario, senha_codificada);
    } else {
        printf("\nA senha não foi encontrada no arquivo.\n");
        salvar_combinacao(senha_usuario, NULL, senha_codificada);
    }


    ///// Liberar memória alocada /////
    for (int i = 0; i < qtd_senhas; i++) {
        free(senhas_codificadas[i]);
    }
    free(senha_codificada);

    return 0;
}