#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMP_CS_SIGNATURE           "COMPCS"
#define COMP_SIGNATURE_LEN          6
#define CURRENT_SETTING_SECTOR_LEN  (0x10000 - 0xc000)

#define N               4096
#define F               18
#define THRESHOLD       2

unsigned char *text_buf;

int Decode(unsigned char *ucInput, unsigned int inLen, unsigned char *ucOutput) {

#if defined(CHEAT_COMPRESS_MIB_SETTING)
    memcpy(ucOutput, ucInput, inLen);
    return inLen;
#else
    int i, j, k, r, c;
    unsigned int flags;
    unsigned int ulPos = 0;
    unsigned int ulExpLen = 0;

    text_buf = malloc(N + F - 1);
    if (!text_buf) {
        fprintf(stderr, "ERR: Failed to allocate text_buf\n");
        return 0;
    }

    for (i = 0; i < N - F; i++)
        text_buf[i] = ' ';
    r = N - F;
    flags = 0;

    while (1) {
        if (((flags >>= 1) & 256) == 0) {
            if (ulPos >= inLen) break;
            c = ucInput[ulPos++];
            flags = c | 0xff00;
        }

        if (flags & 1) {
            if (ulPos >= inLen) break;
            c = ucInput[ulPos++];
            ucOutput[ulExpLen++] = c;
            text_buf[r++] = c;
            r &= (N - 1);
        } else {
            if (ulPos + 1 >= inLen) break;
            i = ucInput[ulPos++];
            j = ucInput[ulPos++];

            i |= ((j & 0xF0) << 4);
            j = (j & 0x0F) + THRESHOLD;

            for (k = 0; k <= j; k++) {
                c = text_buf[(i + k) & (N - 1)];
                ucOutput[ulExpLen++] = c;
                text_buf[r++] = c;
                r &= (N - 1);
            }
        }
    }

    free(text_buf);
    return ulExpLen;
#endif
}

int save_to_file(const char *path, const void *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "ERR: Failed to open output file %s\n", path);
        return 0;
    }
    if (fwrite(data, 1, len, fp) != len) {
        fprintf(stderr, "ERR: Failed to write all data to %s\n", path);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

char *apmib_load_csconf(const char *filename, unsigned int *outLen) {
    FILE *fp;
    unsigned char rawHeader[12];
    unsigned short compRate = 0;
    unsigned int compLen = 0;
    unsigned char *compFile = NULL, *expFile = NULL;
    unsigned int expandLen = 0;

    fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "ERR: Cannot open file %s\n", filename);
        return NULL;
    }

    if (fread(rawHeader, 1, 12, fp) != 12) {
        fprintf(stderr, "ERR: Failed to read header from %s\n", filename);
        fclose(fp);
        return NULL;
    }

    if (memcmp(rawHeader, COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN) != 0) {
        fprintf(stderr, "ERR: Invalid signature in %s\n", filename);
        fclose(fp);
        return NULL;
    }

    compRate = (rawHeader[6] << 8) | rawHeader[7];
    compLen  = (rawHeader[8] << 24) | (rawHeader[9] << 16) | (rawHeader[10] << 8) | rawHeader[11];

    printf("DEBUG: compRate = %u, compLen = %u\n", compRate, compLen);

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 12, SEEK_SET);

    if ((long)(12 + compLen) > fileSize || compLen == 0 || compLen > CURRENT_SETTING_SECTOR_LEN) {
        fprintf(stderr, "ERR: Invalid compressed length (%u) or exceeds file size (%ld)\n", compLen, fileSize);
        fclose(fp);
        return NULL;
    }

    compFile = calloc(1, compLen);
    if (!compFile) {
        fprintf(stderr, "ERR: Failed to allocate memory for compressed data\n");
        fclose(fp);
        return NULL;
    }

    expFile = calloc(1, compRate * compLen);  // rough estimation
    if (!expFile) {
        fprintf(stderr, "ERR: Failed to allocate memory for expanded data\n");
        free(compFile);
        fclose(fp);
        return NULL;
    }

    if (fread(compFile, 1, compLen, fp) != compLen) {
        fprintf(stderr, "ERR: Failed to read compressed data from %s\n", filename);
        free(compFile);
        free(expFile);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    expandLen = Decode(compFile, compLen, expFile);
    if (expandLen == 0) {
        fprintf(stderr, "ERR: Decode failed\n");
        free(compFile);
        free(expFile);
        return NULL;
    }

    printf("DEBUG: Decompressed length = %u bytes\n", expandLen);

    free(compFile);
    *outLen = expandLen;
    return (char *)expFile;
}

int main() {
    const char *inputFile = "config.dat";
    const char *outputFile = "config_decoded.dat";
    unsigned int decompressedLen = 0;

    char *decompressed = apmib_load_csconf(inputFile, &decompressedLen);
    if (!decompressed) {
        fprintf(stderr, "ERROR: Failed to decompress %s\n", inputFile);
        return 1;
    }

    if (!save_to_file(outputFile, decompressed, decompressedLen)) {
        fprintf(stderr, "ERROR: Failed to write to %s\n", outputFile);
        free(decompressed);
        return 1;
    }

    printf("SUCCESS: Decompressed data written to %s (%u bytes)\n", outputFile, decompressedLen);
    free(decompressed);
    return 0;
}

