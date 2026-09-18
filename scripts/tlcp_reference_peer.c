/* Test transport adapter for an unmodified openHiTLS build. Not linked into JinguiSSL. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hitls.h"
#include "hitls_cert.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_pki_cert.h"
#include "bsl_uio.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_init.h"

static void die(const char *operation, int code)
{
    fprintf(stderr, "%s failed: 0x%x\n", operation, code);
    exit(1);
}
#define CHECK(call) do { int status_ = (call); if (status_ != 0) die(#call, status_); } while (0)
static bool retry(int status)
{
    return status == HITLS_REC_NORMAL_RECV_BUF_EMPTY || status == HITLS_REC_NORMAL_IO_BUSY;
}
static void identity(HITLS_Config *config, const char *folder, const char *role)
{
    char path[4096];
    for (int enc = 0; enc < 2; ++enc) {
        HITLS_X509_Cert *cert = NULL;
        CRYPT_EAL_PkeyCtx *key = NULL;
        snprintf(path, sizeof(path), "%s/%s-%s.pem", folder, role, enc ? "enc" : "sign");
        CHECK(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, &cert));
        snprintf(path, sizeof(path), "%s/%s-%s.key", folder, role, enc ? "enc" : "sign");
        CHECK(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, path, NULL, 0, &key));
        CHECK(HITLS_CFG_SetTlcpCertificate(config, cert, true, enc != 0));
        CHECK(HITLS_CFG_SetTlcpPrivateKey(config, key, true, enc != 0));
        HITLS_X509_CertFree(cert); CRYPT_EAL_PkeyFreeCtx(key);
    }
    HITLS_X509_Cert *root = NULL;
    snprintf(path, sizeof(path), "%s/root.pem", folder);
    CHECK(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, &root));
    CHECK(HITLS_CFG_AddCertToStore(config, root, TLS_CERT_STORE_TYPE_DEFAULT, true));
    HITLS_X509_CertFree(root);
}
static void write_data(HITLS_Ctx *ctx)
{
    const char *message = "hitls-to-jinguissl\n";
    uint32_t written = 0;
    for (int n = 0; n < 2000; ++n) {
        int status = HITLS_Write(ctx, (const uint8_t *)message, (uint32_t)strlen(message), &written);
        if (status == 0) {
            if (written != strlen(message)) die("short application write", -1);
            return;
        }
        if (!retry(status)) die("application write", status);
        usleep(10000);
    }
    die("write deadline", -1);
}
static void read_data(HITLS_Ctx *ctx)
{
    uint8_t bytes[1024];
    uint32_t count = 0;
    for (int n = 0; n < 2000; ++n) {
        int status = HITLS_Read(ctx, bytes, sizeof(bytes), &count);
        if (status == 0 && count > 0) {
            const char *expected = "jinguissl-to-hitls\n";
            if (count != strlen(expected) || memcmp(bytes, expected, count) != 0) die("application mismatch", -1);
            fwrite(bytes, 1, count, stdout); fflush(stdout);
            return;
        }
        if (status != 0 && !retry(status)) die("application read", status);
        usleep(10000);
    }
    die("read deadline", -1);
}
int main(int argc, char **argv)
{
    if (argc != 5) { fprintf(stderr, "usage: client|server port suite fixture-folder\n"); return 2; }
    alarm(30);
    bool client = strcmp(argv[1], "client") == 0;
    CHECK(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL));
    CHECK(HITLS_CertMethodInit()); HITLS_CryptMethodInit();
    HITLS_Config *config = HITLS_CFG_NewTLCPConfig();
    if (config == NULL) die("config", -1);
    uint16_t suite = (uint16_t)strtoul(argv[3], NULL, 0);
    CHECK(HITLS_CFG_SetCipherSuites(config, &suite, 1));
    CHECK(HITLS_CFG_SetVerifyNoneSupport(config, false));
    CHECK(HITLS_CFG_SetClientVerifySupport(config, true));
    CHECK(HITLS_CFG_SetNoClientCertSupport(config, false));
    identity(config, argv[4], argv[1]);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET; address.sin_port = htons((uint16_t)atoi(argv[2]));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket", -1);
    if (client) {
        if (connect(fd, (struct sockaddr *)&address, sizeof(address))) die("connect", -1);
    } else {
        int enabled = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 1)) die("listen", -1);
        int accepted = accept(fd, NULL, NULL); close(fd); fd = accepted;
        if (fd < 0) die("accept", -1);
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) die("nonblocking", -1);
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) die("UIO", -1);
    CHECK(BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(fd), &fd));
    HITLS_Ctx *ctx = HITLS_New(config);
    if (ctx == NULL) die("context", -1);
    CHECK(HITLS_SetUio(ctx, uio));
    int status = -1;
    for (int n = 0; n < 2000; ++n) {
        status = client ? HITLS_Connect(ctx) : HITLS_Accept(ctx);
        if (status == 0) break;
        if (!retry(status)) die("handshake", status);
        usleep(10000);
    }
    if (status != 0) die("handshake deadline", status);
    HITLS_ERROR verification = 0;
    CHECK(HITLS_GetVerifyResult(ctx, &verification));
    if (verification != 0) die("peer verification", verification);
    uint16_t version = 0, negotiated = 0;
    CHECK(HITLS_GetNegotiatedVersion(ctx, &version));
    CHECK(HITLS_CFG_GetCipherSuite(HITLS_GetCurrentCipher(ctx), &negotiated));
    if (version != 0x0101 || negotiated != suite) die("negotiation mismatch", -1);
    printf("TLS handshake completed successfully suite=0x%x verified=true\n", negotiated); fflush(stdout);
    if (client) { write_data(ctx); read_data(ctx); }
    else { read_data(ctx); write_data(ctx); }
    for (int n = 0; n < 100; ++n) { if (!retry(HITLS_Close(ctx))) break; usleep(10000); }
    HITLS_Free(ctx); BSL_UIO_Free(uio); close(fd); HITLS_CFG_FreeConfig(config);
    return 0;
}
