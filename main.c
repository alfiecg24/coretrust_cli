#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <TargetConditionals.h>

#include <choma/MachO.h>
#include <choma/FAT.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/Host.h>
#include <choma/CSBlob.h>

#include "CoreTrust.h"

char *get_argument_value(int argc, char *argv[], const char *flag) {
  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], flag)) {
      if (i + 1 < argc) {
        return argv[i + 1];
      }
    }
  }
  return NULL;
}

bool argument_exists(int argc, char *argv[], const char *flag) {
  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], flag)) {
      return true;
    }
  }
  return false;
}

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);

#if TARGET_OS_MAC && !TARGET_OS_IPHONE
    if (!macho) {
        // Check for arm64v8 first
        macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8);
        if (!macho) {
            // If that fails, check for regular arm64
            macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
            if (!macho) {
                // If that fails, check for arm64e with ABI v2
                macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
                if (!macho) {
                    // If that fails, check for arm64e
                    macho = fat_find_slice(fat, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
                    if (!macho) {
                        fat_free(fat);
                        return NULL;
                    }
                }
            }
        }
    }
#else
    if (!macho) {
        fat_free(fat);
        return NULL;
    }
#endif // TARGET_OS_MAC && !TARGET_OS_IPHONE

    if (macho->machHeader.filetype == MH_OBJECT) {
        printf("Error: MachO is an object file, please use a MachO executable or dynamic library!\n");
        fat_free(fat);
        return NULL;
    }

    if (macho->machHeader.filetype == MH_DSYM) {
        printf("Error: MachO is a dSYM file, please use a MachO executable or dynamic library!\n");
        fat_free(fat);
        return NULL;
    }
    
    char *temp = strdup("/tmp/XXXXXX");
    int fd = mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    close(fd);
    return temp;
}

void print_usage(const char *self) {
  printf("Options: \n");
  printf("\t-i: input file\n");
  printf("\t-h: print this help message\n");
  printf("Examples:\n");
  printf("\t%s -i <path to input binary>\n", self);
  exit(-1);
}

void evaluate_code_signature(CT_uint8_t *cmsData, CT_size_t cmsLen,
                             CT_uint8_t *codeDirectoryData,
                             CT_size_t codeDirectoryLen) {
  const CT_uint8_t *leafCert = NULL;
  CT_size_t leafCertLen = 0;
  CoreTrustPolicyFlags policyFlags = 0;
  CoreTrustDigestType cmsDigestType = 0;
  CoreTrustDigestType hashAgilityDigestType = 0;
  const CT_uint8_t *digestData = NULL;
  CT_size_t digestLen = 0;

  CT_int result = CTEvaluateAMFICodeSignatureCMS(
      cmsData, cmsLen, codeDirectoryData, codeDirectoryLen, false, &leafCert,
      &leafCertLen, &policyFlags, &cmsDigestType, &hashAgilityDigestType,
      &digestData, &digestLen);

  if (result == 0) {
    if (policyFlags == 0) {
      printf("CoreTrust evaluation was successful, but there were no matching "
             "policies found for the certificate.\n");
      return;
    }

    printf("CoreTrust evaluation was successful!\n");
    printPolicyInformation(policyFlags);

    if (hashAgilityDigestType != 0) {
      printf("CMS uses Apple Hash Agility V2, chosen hash type is ");
      printDigestType(hashAgilityDigestType);
      printf(".\n");
      
    } else if (digestLen != 0) {
      printf("CMS uses Apple Hash Agility v1.\n");
    } else {
      printf("CMS does not use Apple Hash Agility!\n");
      return;
    }

    printf("AMFI will expect CD hash of ");
    printDigestType(cmsDigestType);
    printf(" code directory to be ");
    for (CT_size_t i = 0; i < digestLen; i++) {
      printf("%02x", digestData[i]);
    }
    printf(".\n");

  } else {
    printf("Error: CTEvaluateAMFICodeSignatureCMS returned 0x%x.\n", result);
  }
}

int main(int argc, char *argv[]) {
  const char *inputPath = get_argument_value(argc, argv, "-i");
  if (!inputPath) {
    print_usage(argv[0]);
  }

  char *preferredSlice = extract_preferred_slice(inputPath);
  if (!preferredSlice) {
        printf("Error: failed to extract preferred slice!\n");
        return -1;
  }

  MachO *macho = macho_init_for_writing(preferredSlice);
  if (!macho) {
    free(preferredSlice);
    return -1;
  }

  CS_SuperBlob *superblob = macho_read_code_signature(macho);
  if (!superblob) {
      printf("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
      free(preferredSlice);
      return -1;
  }

  CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
  CS_DecodedBlob *signatureBlob = csd_superblob_find_blob(decodedSuperblob, CSSLOT_SIGNATURESLOT, NULL);
  if (!signatureBlob) {
      printf("Error: no signature blob found!\n");
      free(preferredSlice);
      return -1;
  }

  size_t sigBlobLen = csd_blob_get_size(signatureBlob) - 8;
  uint8_t *sigBlob = malloc(sigBlobLen);
  csd_blob_read(signatureBlob, 8, sigBlobLen, sigBlob);

  CS_DecodedBlob *codeDirectory = csd_superblob_find_blob(decodedSuperblob, CSSLOT_CODEDIRECTORY, NULL);
  if (!codeDirectory) {
      printf("Error: no code directory found!\n");
      free(preferredSlice);
      return -1;
  }

  size_t codeDirectoryBlobLen = csd_blob_get_size(codeDirectory);
  uint8_t *codeDirectoryBlob = malloc(codeDirectoryBlobLen);
  csd_blob_read(codeDirectory, 0, codeDirectoryBlobLen, codeDirectoryBlob);

  csd_superblob_free(decodedSuperblob);
  free(preferredSlice);

  evaluate_code_signature(sigBlob, sigBlobLen, codeDirectoryBlob, codeDirectoryBlobLen);

  free(sigBlob);
  free(codeDirectoryBlob);

  return 0;
}
