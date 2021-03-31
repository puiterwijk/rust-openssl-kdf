#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>

// These values are from the CAVP test vectors for SP 800-108
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation
// Selected test:
// PRF=HMAC_SHA256
// CTRLOCATION=BEFORE_FIXED
// RLEN=8_bits
// COUNT=0
const char *INPUT_KI = "3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83";
const char *INPUT_Label = "deadbeef";
const char *INPUT_Context = "deadbeef";
int INPUT_L = 128;

int main()
{
    int rc;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *KI, *Label, *Context;
    long ki_len, label_len, context_len;
    unsigned char outbuf[20];
    char *outstr;

    // First, th conversions from hex to binary
    KI = OPENSSL_hexstr2buf(INPUT_KI, &ki_len);
    Label = OPENSSL_hexstr2buf(INPUT_Label, &label_len);
    Context = OPENSSL_hexstr2buf(INPUT_Context, &context_len);
    if (KI == NULL || Label == NULL || Context == NULL)
    {
        printf("One of the hex2buf conversions failed\n");
        return 1;
    }

    // Now, configure the KBKDF
    kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB);
    if (kctx == NULL)
    {
        printf("Error initializing KDF\n");
        rc = 0;
        goto out;
    }

    rc = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MODE, EVP_KDF_KB_MODE_COUNTER);
    if (rc != 1)
        goto out;

    rc = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_HMAC);
    if (rc != 1)
        goto out;

    rc = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, Label, label_len);
    if (rc != 1)
        goto out;

    rc = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_INFO, Context, context_len);
    if (rc != 1)
        goto out;

    rc = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, KI, ki_len);
    if (rc != 1)
        goto out;

    rc = EVP_KDF_ctrl_str(kctx, "digest", "sha256");
    if (rc != 1)
        goto out;

    printf("Performing the derivation\n");

    rc = EVP_KDF_derive(kctx, outbuf, 20);
    if (rc != 1)
        goto out;

    outstr = OPENSSL_buf2hexstr(outbuf, 20);
    if (outstr == NULL)
    {
        printf("Error converting out key\n");
        rc = 0;
        goto out;
    }

    printf("Derived key: %s\n", outstr);

out:
    EVP_KDF_CTX_free(kctx);
    if (rc != 1)
        printf("Error encountered: %d\n", rc);
    return rc;
}
