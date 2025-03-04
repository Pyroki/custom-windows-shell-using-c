#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <conio.h>   // For _getch()
#include <fcntl.h>
#include <openssl/evp.h> // Modern OpenSSL 3.0 API
#include <openssl/sha.h>

#define MAX_CMD_LEN 1024
#define HISTORY_SIZE 10  // Store last 10 commands
#define ALIAS_COUNT 10   // Max number of aliases
#define XOR_KEY 0x5A     // Key for XOR encryption

char history[HISTORY_SIZE][MAX_CMD_LEN];
int history_count = 0;
int history_index = -1;

struct alias {
    char name[50];
    char command[100];
};

struct alias alias_table[ALIAS_COUNT];
int alias_count = 0;

void xor_encrypt_decrypt(char *filename) {
    FILE *file = fopen(filename, "rb+");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return;
    }
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);
    
    char *buffer = (char *)malloc(filesize);
    fread(buffer, 1, filesize, file);
    for (long i = 0; i < filesize; i++) {
        buffer[i] ^= XOR_KEY;
    }
    rewind(file);
    fwrite(buffer, 1, filesize, file);
    fclose(file);
    free(buffer);
    printf("File %s has been encrypted/decrypted.\n", filename);
}

void sha256_hash(char *input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    printf("SHA-256: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void sha256_hash_file(char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[1024];
    size_t bytesRead;

    EVP_DigestInit_ex(ctx, md, NULL);
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(ctx, buffer, bytesRead);
    }
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    fclose(file);

    printf("SHA-256 hash of %s: ", filename);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void execute_command(char *command) {
    if (strncmp(command, "encrypt ", 8) == 0) {
        xor_encrypt_decrypt(command + 8);
        return;
    }
    if (strncmp(command, "hash ", 5) == 0) {
        sha256_hash(command + 5);
        return;
    }
    if (strncmp(command, "hashfile ", 9) == 0) {
        sha256_hash_file(command + 9);
        return;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "cmd /c \"%s\"", command);

    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to execute command: %s\n", command);
    } else {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int main() {
    char command[MAX_CMD_LEN];
    printf("Secure Windows Shell with Cryptography\n");

    while (1) {
        printf("myshell> ");
        fgets(command, MAX_CMD_LEN, stdin);
        command[strcspn(command, "\n")] = 0;
        if (strcmp(command, "exit") == 0) break;
        execute_command(command);
    }
    return 0;
}
