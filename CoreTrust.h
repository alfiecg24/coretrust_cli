#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

typedef uint8_t CT_uint8_t;
typedef uint32_t CT_uint32_t;
typedef uint64_t CT_uint64_t;
typedef size_t CT_size_t;
typedef int CT_int;
typedef bool CT_bool;

typedef struct x509_octet_string {
    const CT_uint8_t *data;
    CT_size_t length;
} CTAsn1Item;

typedef CT_uint64_t CoreTrustPolicyFlags;
enum {
    CORETRUST_POLICY_BASIC =                0,
    CORETRUST_POLICY_SAVAGE_DEV =           1 << 0,
    CORETRUST_POLICY_SAVAGE_PROD =          1 << 1,
    CORETRUST_POLICY_MFI_AUTHV3 =           1 << 2,
    CORETRUST_POLICY_MAC_PLATFORM =         1 << 3,
    CORETRUST_POLICY_MAC_DEVELOPER =        1 << 4,
    CORETRUST_POLICY_DEVELOPER_ID =         1 << 5,
    CORETRUST_POLICY_MAC_APP_STORE =        1 << 6,
    CORETRUST_POLICY_IPHONE_DEVELOPER =     1 << 7,
    CORETRUST_POLICY_IPHONE_APP_PROD =      1 << 8,
    CORETRUST_POLICY_IPHONE_APP_DEV =       1 << 9,
    CORETRUST_POLICY_IPHONE_VPN_PROD =      1 << 10,
    CORETRUST_POLICY_IPHONE_VPN_DEV =       1 << 11,
    CORETRUST_POLICY_TVOS_APP_PROD =        1 << 12,
    CORETRUST_POLICY_TVOS_APP_DEV =         1 << 13,
    CORETRUST_POLICY_TEST_FLIGHT_PROD =     1 << 14,
    CORETRUST_POLICY_TEST_FLIGHT_DEV =      1 << 15,
    CORETRUST_POLICY_IPHONE_DISTRIBUTION =  1 << 16,
    CORETRUST_POLICY_MAC_SUBMISSION =       1 << 17,
    CORETRUST_POLICY_YONKERS_DEV =          1 << 18,
    CORETRUST_POLICY_YONKERS_PROD =         1 << 19,
    CORETRUST_POLICY_MAC_PLATFORM_G2 =      1 << 20,
    CORETRUST_POLICY_ACRT =                 1 << 21,
    CORETRUST_POLICY_SATORI =               1 << 22,
    CORETRUST_POLICY_BAA =                  1 << 23,
    CORETRUST_POLICY_BAA_SYSTEM =           1 << 23, // BAA and BAA_SYSTEM are the same
    CORETRUST_POLICY_UCRT =                 1 << 24,
    CORETRUST_POLICY_PRAGUE =               1 << 25,
    CORETRUST_POLICY_KDL =                  1 << 26,
    CORETRUST_POLICY_MFI_AUTHV2 =           1 << 27,
    CORETRUST_POLICY_MFI_SW_AUTH_PROD =     1 << 28,
    CORETRUST_POLICY_MFI_SW_AUTH_DEV =      1 << 29,
    CORETRUST_POLICY_COMPONENT =            1 << 30,
    CORETRUST_POLICY_IMG4 =                 1ULL << 31,
    CORETRUST_POLICY_SERVER_AUTH =          1ULL << 32,
    CORETRUST_POLICY_SERVER_AUTH_STRING =   1ULL << 33,
    CORETRUST_POLICY_MFI_AUTHV4_ACCESSORY = 1ULL << 34,
    CORETRUST_POLICY_MFI_AUTHV4_ATTESTATION = 1ULL << 35,
    CORETRUST_POLICY_MFI_AUTHV4_PROVISIONING = 1ULL << 36,
    CORETRUST_POLICY_WWDR_CLOUD_MANAGED =   1ULL << 37,
    CORETRUST_POLICY_HAVEN =                1ULL << 38,
    CORETRUST_POLICY_PROVISIONING_PROFILE = 1ULL << 39,
    CORETRUST_POLICY_SENSOR_PROD =          1ULL << 40,
    CORETRUST_POLICY_SENSOR_DEV =           1ULL << 41,
    CORETRUST_POLICY_BAA_USER =             1ULL << 42,
};

void printPolicyInformation(CoreTrustPolicyFlags policyFlags) {
    printf("CoreTrust policy flags (0x%llx):\n", policyFlags);
    if (policyFlags & CORETRUST_POLICY_BASIC) {
        printf(" - Basic\n");
    }
    if (policyFlags & CORETRUST_POLICY_SAVAGE_DEV) {
        printf(" - Savage (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_SAVAGE_PROD) {
        printf(" - Savage (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_AUTHV3) {
        printf(" - MFi Auth v3\n");
    }
    if (policyFlags & CORETRUST_POLICY_MAC_PLATFORM) {
        printf(" - Mac Platform\n");
    }
    if (policyFlags & CORETRUST_POLICY_MAC_DEVELOPER) {
        printf(" - Mac Developer\n");
    }
    if (policyFlags & CORETRUST_POLICY_DEVELOPER_ID) {
        printf(" - Developer ID\n");
    }
    if (policyFlags & CORETRUST_POLICY_MAC_APP_STORE) {
        printf(" - Mac App Store\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_DEVELOPER) {
        printf("  iPhone Developer\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_APP_PROD) {
        printf(" - iPhone App Store\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_APP_DEV) {
        printf(" - iPhone App (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_VPN_PROD) {
        printf(" - iPhone VPN (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_VPN_DEV) {
        printf(" - iPhone VPN (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_TVOS_APP_PROD) {
        printf(" - tvOS App Store\n");
    }
    if (policyFlags & CORETRUST_POLICY_TVOS_APP_DEV) {
        printf(" - tvOS App (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_TEST_FLIGHT_PROD) {
        printf(" - TestFlight (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_TEST_FLIGHT_DEV) {
        printf(" - TestFlight (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_IPHONE_DISTRIBUTION) {
        printf(" - iPhone (Distribution)\n");
    }
    if (policyFlags & CORETRUST_POLICY_MAC_SUBMISSION) {
        printf(" - Mac Submission\n");
    }
    if (policyFlags & CORETRUST_POLICY_YONKERS_DEV) {
        printf(" - Yonkers (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_YONKERS_PROD) {
        printf(" - Yonkers (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_MAC_PLATFORM_G2) {
        printf(" - Mac Platform G2\n");
    }
    if (policyFlags & CORETRUST_POLICY_ACRT) {
        printf(" - ACRT\n");
    }
    if (policyFlags & CORETRUST_POLICY_SATORI) {
        printf(" - Satori\n");
    }
    if (policyFlags & CORETRUST_POLICY_BAA) {
        printf(" - BAA\n");
    }
    if (policyFlags & CORETRUST_POLICY_UCRT) {
        printf(" - UCRT\n");
    }
    if (policyFlags & CORETRUST_POLICY_PRAGUE) {
        printf(" - Prague\n");
    }
    if (policyFlags & CORETRUST_POLICY_KDL) {
        printf(" - KDL\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_AUTHV2) {
        printf(" - MFi Auth v2\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_SW_AUTH_PROD) {
        printf(" - MFi SW Auth (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_SW_AUTH_DEV) {
        printf(" - MFi SW Auth (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_COMPONENT) {
        printf(" - Component\n");
    }
    if (policyFlags & CORETRUST_POLICY_IMG4) {
        printf(" - IMG4\n");
    }
    if (policyFlags & CORETRUST_POLICY_SERVER_AUTH) {
        printf(" - Server Auth\n");
    }
    if (policyFlags & CORETRUST_POLICY_SERVER_AUTH_STRING) {
        printf(" - Server Auth String\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_AUTHV4_ACCESSORY) {
        printf(" - MFi Auth v4 Accessory\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_AUTHV4_ATTESTATION) {
        printf(" - MFi Auth v4 Attestation\n");
    }
    if (policyFlags & CORETRUST_POLICY_MFI_AUTHV4_PROVISIONING) {
        printf(" - MFi Auth v4 Provisioning\n");
    }
    if (policyFlags & CORETRUST_POLICY_WWDR_CLOUD_MANAGED) {
        printf(" - WWDR (Cloud Managed)\n");
    }
    if (policyFlags & CORETRUST_POLICY_HAVEN) {
        printf(" - Haven\n");
    }
    if (policyFlags & CORETRUST_POLICY_PROVISIONING_PROFILE) {
        printf("  Provisioning Profile\n");
    }
    if (policyFlags & CORETRUST_POLICY_SENSOR_PROD) {
        printf(" - Sensor (Production)\n");
    }
    if (policyFlags & CORETRUST_POLICY_SENSOR_DEV) {
        printf(" - Sensor (Development)\n");
    }
    if (policyFlags & CORETRUST_POLICY_BAA_USER) {
        printf(" - BAA User\n");
    }
    printf("\n");
}

typedef CT_uint32_t CoreTrustDigestType;
enum {
    CORETRUST_DIGEST_TYPE_SHA1 = 1,
    CORETRUST_DIGEST_TYPE_SHA224 = 2,
    CORETRUST_DIGEST_TYPE_SHA256 = 4,
    CORETRUST_DIGEST_TYPE_SHA384 = 8,
    CORETRUST_DIGEST_TYPE_SHA512 = 16
};

void printDigestType(CoreTrustDigestType digestType) {
    switch (digestType) {
        case CORETRUST_DIGEST_TYPE_SHA1:
            printf("SHA-1");
            break;
        case CORETRUST_DIGEST_TYPE_SHA224:
            printf("SHA-224");
            break;
        case CORETRUST_DIGEST_TYPE_SHA256:
            printf("SHA-256");
            break;
        case CORETRUST_DIGEST_TYPE_SHA384:
            printf("SHA-384");
            break;
        case CORETRUST_DIGEST_TYPE_SHA512:
            printf("SHA-512");
            break;
        default:
            printf("unknown");
            break;
    }
}

/*! @function CTEvaluateAMFICodeSignatureCMS
 @abstract Verify CMS signature and certificates against the AMFI policies
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param detachedData pointer to data that is signed by the CMS object
 @param detachedDataLen the length of the signed data
 @param allow_test_hierarchy allow the Test Apple roots to be used as anchors  in addition to the production roots
 @param leafCert return value, pointer to the verified leaf certificate
 @param leafCertLen return value, length of the verified leaf certificate
 @param policyFlags return value, the CoreTrust policies that the certificate chain met
 @param cmsDigestType return value, the digest type used to sign the CMS object
 @param hashAgilityDigestType return value, the highest strength digest type available in the hash agility attribute
 @param digestData return value, pointer to the hash agility value
 @param digestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
CT_int CTEvaluateAMFICodeSignatureCMS(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,
    const CT_uint8_t *detachedData, CT_size_t detachedDataLen,
    CT_bool allow_test_hierarchy,
    const CT_uint8_t **leafCert, CT_size_t *leafCertLen,
    CoreTrustPolicyFlags *policyFlags,
    CoreTrustDigestType *cmsDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t **digestData, CT_size_t *digestLen);

/*! @function CTVerifyAmfiCMS
 @abstract Verify CMS signed data signature
 @param cmsData  pointer to beginning of the binary (BER-encoded) CMS object
 @param cmsLen the length of the CMS object
 @param digestData  pointer to beginning of the content data hash
 @param digestLen the length of the content data hash
 @param maxDigestType maximum digest type supported by the client
 @param hashAgilityDigestType return value, the highest strength digest type available in the hash agility attribute
 @param hashAgilityDigestData return value, pointer to the hash agility value
 @param hashAgilityDigestLen return value, length of the hash agility value
 @return 0 upon success, a parsing or validation error (see CTErrors.h)
 @discussion
 Returns non-zero if there's a standards-based problem with the CMS or certificates.
 Some notes about hash agility outputs:
 - hashAgilityDigestType is only non-zero for HashAgilityV2
 - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */
CT_int CTVerifyAmfiCMS(
    const CT_uint8_t *cmsData, CT_size_t cmsLen,
    const CT_uint8_t *digestData, CT_size_t digestLen,
    CoreTrustDigestType maxDigestType,
    CoreTrustDigestType *hashAgilityDigestType,
    const CT_uint8_t **hashAgilityDigestData, CT_size_t *hashAgilityDigestLen);
