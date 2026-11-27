/*
 * cert.hpp
 * Ed25519 certificate chain verification and configuration jwt verification
 * Header-only, platform independent, C++11 (g++ and MSVC v141, Windows XP target)
 *
 * A security agent downloads a configuration token from a server over a plain channel. The
 * token is a jwt-like string "header_b64.payload_b64.signature_b64" (base64url without
 * padding). The header carries exactly one DER encoded X.509 certificate in "x5c". The agent
 * embeds one root Ed25519 public key and accepts the token only when the certificate is
 * signed by that root and the jwt is signed by the certificate's key:
 *
 *   R1  the token has exactly three segments; the header is a JSON object whose alg is
 *       "EdDSA" and whose x5c is an array with exactly one string; the payload is a JSON
 *       object with group (string), serial, iat, exp (integers) and config (object)
 *   R2  every base64url segment decodes and the certificate is well-formed DER that matches
 *       the certificate template
 *   R3  both algorithm identifiers of the certificate and the algorithm of its subject
 *       public key are Ed25519 (1.3.101.112) without parameters. The size of the subject
 *       public key is read during R2; a size other than 32 bytes is a violation of R3 when
 *       the algorithm of the key is not Ed25519, and a violation of R2 otherwise.
 *   R4  the certificate signature over tbsCertificate verifies with the root public key
 *   R5  notBefore - 86400 <= now <= notAfter
 *   R6  the third segment decodes to 64 bytes that are a valid Ed25519 signature by the
 *       certificate public key over the original text "header_b64.payload_b64"
 *   R8  iat - 86400 <= now <= exp
 *
 * The rules are checked in this order and the first violation is reported with the error
 * code RuleViolatedBase + <rule number>. An installed configuration stays valid forever, so
 * callers re-check it with VerifyConfigJwt(..., SkipTime), which leaves out R5 and R8.
 *
 * The module never opens a file, never reads the clock and does not call any platform API.
 * The caller provides the time. All functions are pure and may run on several threads.
 */

#ifndef CPL_CERT_HPP_ORBIT_LANTERN_MODERN_CAPTURE_SEASON_GLACIER_TEXTBOOK_PICNIC_CREDIT
#define CPL_CERT_HPP_ORBIT_LANTERN_MODERN_CAPTURE_SEASON_GLACIER_TEXTBOOK_PICNIC_CREDIT

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "base.hpp"
#include "naion.hpp"
#include "vendor/nlohmann/json/json.hpp"

namespace cpl {
    namespace cert {
        // Error codes. A violated rule is reported as RuleViolatedBase + <rule number>.
        enum : int64_t {
            CertParseError   = 0x40000001,  // malformed DER or malformed certificate
            JwtFormatError   = 0x40000002,  // not three segments, bad base64url, bad JSON
            RuleViolatedBase = 0x40000100,  // add the rule number (1..8)
        };
        // Where the codes are used:
        //   ParseCertificate  reports every failure with CertParseError; its reason names R2 or R3.
        //   VerifyIssuedBy    reports RuleViolatedBase + 4 or + 5.
        //   VerifyConfigJwt   reports RuleViolatedBase + <rule> for every failure. The three
        //                     problems listed for JwtFormatError violate R1 or R2, so they are
        //                     reported as RuleViolatedBase + 1 or + 2 as well.

        struct Certificate {
            Stream tbs;                           // DER encoding of tbsCertificate
            Stream signature;                     // signature bytes
            std::array<uint8_t, 32> publicKey{};  // Ed25519 public key from subjectPublicKeyInfo
            int64_t notBefore = 0;                // Unix seconds (UTC)
            int64_t notAfter = 0;                 // Unix seconds (UTC)
        };

        struct VerifiedJwt {
            std::string payloadJson;  // decoded payload
            std::string group;        // payload.group
            int64_t serial = 0;       // payload.serial
        };

        // EnforceTime applies R5 and R8. SkipTime leaves both rules out (load-time check of an
        // already installed configuration).
        enum TimeCheck {
            EnforceTime = 0,
            SkipTime = 1,
        };

        namespace impl {
            // Identifier octets of the elements of the certificate template. Only tags with a
            // number up to 30 fit into one octet; the high tag number form is rejected.
            enum : uint8_t {
                TagInteger         = 0x02,
                TagBitString       = 0x03,
                TagUtcTime         = 0x17,
                TagGeneralizedTime = 0x18,
                TagSequence        = 0x30,
                TagVersion         = 0xA0,  // [0] EXPLICIT version
                TagIssuerUniqueId  = 0x81,  // [1] IMPLICIT issuerUniqueID
                TagSubjectUniqueId = 0x82,  // [2] IMPLICIT subjectUniqueID
                TagExtensions      = 0xA3,  // [3] EXPLICIT extensions
            };

            // Sizes fixed by Ed25519 and the one day grace of R5 and R8.
            enum : size_t {
                PublicKeyBytes = 32,
                SignatureBytes = 64,
            };
            enum : int64_t {
                GraceSeconds = 86400,
            };
            // Nesting levels accepted when the content of a skipped element is checked.
            enum : int {
                DerMaxDepth = 16,
            };

            // One decoded TLV: the identifier octet and the location of the other octets.
            struct DerElement {
                uint8_t tag = 0;          // identifier octet
                const uint8_t *start = nullptr;
                const uint8_t *content = nullptr;
                size_t contentSize = 0;
                size_t totalSize = 0;     // identifier + length + content
            };

            // Builds the error of a defect found by the DER reader. A certificate that cannot be
            // read element by element is not valid DER, so the defect always violates R2.
            inline cpl::Err DerError(const char *defect) {
                return cpl::MakeErr(RuleViolatedBase + 2,
                                    std::string("[X] cert: rule R2 der ") + defect + " " CPL_FILE_AND_LINE);
            }

            // Reads the identifier and the length octets at the start of [data, data + size).
            // Returns nullptr when the header is well-formed and fills element; otherwise it
            // returns a phrase that names the defect. Accepted is exactly what DER allows:
            //   - one identifier octet, i.e. a tag number up to 30
            //   - the short form of the length, or the long form with one to four octets that
            //     together encode at least 128 (a longer form for a shorter value is over-long)
            // The indefinite form, the reserved length octet 0xFF, over-long forms, truncated
            // elements and tags of the high tag number form are rejected.
            inline const char *DerReadHeader(const uint8_t *data, const size_t size, DerElement &element) {
                if (size == 0) {
                    return "element is truncated";
                }
                const uint8_t tag = data[0];
                if ((tag & 0x1F) == 0x1F) {
                    return "tag uses the high tag number form";
                }
                if (size == 1) {
                    return "element is truncated";
                }
                const uint8_t first = data[1];
                uint64_t length = 0;
                size_t headerSize = 2;
                if (first < 0x80) {
                    // Short form.
                    length = first;
                } else {
                    if (first == 0x80) {
                        return "length uses the indefinite form";
                    }
                    if (first == 0xFF) {
                        return "length octet is reserved";
                    }
                    const size_t count = first & 0x7F;
                    if (count > 4) {
                        return "length is longer than four octets";
                    }
                    if (size < 2 + count) {
                        return "element is truncated";
                    }
                    if (data[2] == 0) {
                        return "length is over-long";
                    }
                    for (size_t i = 0; i < count; i++) {
                        length = (length << 8) | data[2 + i];
                    }
                    if (length < 0x80) {
                        return "length is over-long";
                    }
                    headerSize = 2 + count;
                }
                if (length > static_cast<uint64_t>(size - headerSize)) {
                    return "element is truncated";
                }
                element.tag = tag;
                element.start = data;
                element.content = data + headerSize;
                element.contentSize = static_cast<size_t>(length);
                element.totalSize = headerSize + element.contentSize;
                return nullptr;
            }

            // Splits the content octets of a constructed value into its elements. The elements
            // must cover the content completely, so a nested element can neither be truncated
            // nor reach into a sibling.
            inline cpl::Result<std::vector<DerElement> > DerSplit(const uint8_t *content, const size_t size) {
                std::vector<DerElement> items{};
                size_t offset = 0;
                while (offset < size) {
                    DerElement element{};
                    const char *defect = DerReadHeader(content + offset, size - offset, element);
                    if (defect != nullptr) {
                        return DerError(defect);
                    }
                    items.push_back(element);
                    offset += element.totalSize;
                }
                return items;
            }

            // Checks that [data, data + size) is a run of well-formed elements. The content of
            // constructed elements is checked recursively, at most depth levels deep.
            inline bool DerIsWellFormed(const uint8_t *data, const size_t size, const int depth) {
                size_t offset = 0;
                while (offset < size) {
                    DerElement element{};
                    if (DerReadHeader(data + offset, size - offset, element) != nullptr) {
                        return false;
                    }
                    if ((element.tag & 0x20) != 0) {
                        if (depth <= 0 || !DerIsWellFormed(element.content, element.contentSize, depth - 1)) {
                            return false;
                        }
                    }
                    offset += element.totalSize;
                }
                return true;
            }

            inline bool IsLeapYear(const int64_t year) {
                return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            }

            inline int DaysInMonth(const int64_t year, const int month) {
                static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
                return month == 2 && IsLeapYear(year) ? 29 : days[month - 1];
            }

            // Days from 1970-01-01 to the civil date, proleptic Gregorian calendar.
            inline int64_t DaysFromCivil(int64_t year, const int month, const int day) {
                year -= month <= 2 ? 1 : 0;
                const int64_t era = (year >= 0 ? year : year - 399) / 400;
                const int64_t yearOfEra = year - era * 400;                    // [0, 399]
                const int64_t shiftedMonth = (month + 9) % 12;                 // March is month 0
                const int64_t dayOfYear = (153 * shiftedMonth + 2) / 5 + day - 1;
                const int64_t dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
                return era * 146097 + dayOfEra - 719468;
            }

            // Reads count decimal digits; the caller has checked that they are digits.
            inline int ReadDigits(const uint8_t *text, const size_t count) {
                int value = 0;
                for (size_t i = 0; i < count; i++) {
                    value = value * 10 + static_cast<int>(text[i] - '0');
                }
                return value;
            }

            // Converts an X.509 Time into Unix seconds (UTC). Accepted are only the two forms
            // of RFC 5280: UTCTime "YYMMDDHHMMSSZ" (YY >= 50 means 19YY, else 20YY) and
            // GeneralizedTime "YYYYMMDDHHMMSSZ". No fractions, no offset, no leap second.
            inline bool ParseX509Time(const DerElement &element, int64_t *outUnix) {
                const size_t size = element.contentSize;
                int64_t year = 0;
                size_t yearDigits = 0;
                if (element.tag == TagUtcTime && size == 13) {
                    yearDigits = 2;
                } else if (element.tag == TagGeneralizedTime && size == 15) {
                    yearDigits = 4;
                } else {
                    return false;
                }
                const uint8_t *text = element.content;
                for (size_t i = 0; i + 1 < size; i++) {
                    if (text[i] < '0' || text[i] > '9') {
                        return false;
                    }
                }
                if (text[size - 1] != 'Z') {
                    return false;
                }
                const int twoDigitYear = ReadDigits(text, 2);
                if (yearDigits == 2) {
                    year = twoDigitYear >= 50 ? 1900 + twoDigitYear : 2000 + twoDigitYear;
                } else {
                    year = twoDigitYear * 100 + ReadDigits(text + 2, 2);
                }
                const uint8_t *rest = text + yearDigits;
                const int month = ReadDigits(rest, 2);
                const int day = ReadDigits(rest + 2, 2);
                const int hour = ReadDigits(rest + 4, 2);
                const int minute = ReadDigits(rest + 6, 2);
                const int second = ReadDigits(rest + 8, 2);
                if (month < 1 || month > 12 || day < 1 || day > DaysInMonth(year, month)) {
                    return false;
                }
                if (hour > 23 || minute > 59 || second > 59) {
                    return false;
                }
                *outUnix = DaysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
                return true;
            }

            // The element must be exactly "SEQUENCE { OID 1.3.101.112 }": Ed25519 with absent
            // parameters (RFC 8410). Any other content, including a NULL parameter, is another
            // algorithm.
            inline bool IsEd25519Algorithm(const DerElement &element) {
                static const uint8_t identifier[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};
                return element.totalSize == sizeof(identifier)
                       && std::memcmp(element.start, identifier, sizeof(identifier)) == 0;
            }

            // A BIT STRING whose value occupies a whole number of octets. The first content
            // octet counts the unused bits of the last octet and must be zero; the function
            // returns the value octets.
            inline bool DerBitStringOctets(const DerElement &element, const uint8_t **octets, size_t *size) {
                if (element.contentSize == 0 || element.content[0] != 0) {
                    return false;
                }
                *octets = element.content + 1;
                *size = element.contentSize - 1;
                return true;
            }

            // Parses one certificate and enforces R2 (well-formed DER that matches the template)
            // and R3 (Ed25519 algorithms). Failures carry RuleViolatedBase + 2 or + 3.
            inline cpl::Result<Certificate> ParseCertificateRules(const uint8_t *der, const size_t size) {
                Certificate out{};
                if (size == 0) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 certificate der is empty" CPL_FILE_AND_LINE);
                }
                if (der == nullptr) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 certificate der pointer is null" CPL_FILE_AND_LINE);
                }

                // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
                DerElement certificate{};
                const char *defect = DerReadHeader(der, size, certificate);
                if (defect != nullptr) {
                    return DerError(defect);
                }
                if (certificate.tag != TagSequence) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 certificate is not a sequence" CPL_FILE_AND_LINE);
                }
                if (certificate.totalSize != size) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 trailing garbage after the certificate"
                                        CPL_FILE_AND_LINE);
                }
                const auto outer = DerSplit(certificate.content, certificate.contentSize);
                if (!outer) {
                    return cpl::Err(outer.error());
                }
                if (outer->size() != 3) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 certificate does not have exactly three elements"
                                        CPL_FILE_AND_LINE);
                }
                const DerElement &tbsCertificate = (*outer)[0];
                const DerElement &signatureAlgorithm = (*outer)[1];
                const DerElement &signatureValue = (*outer)[2];

                // Splits the content of an element and hands an error of the reader through.
                const auto splitOf = [](const DerElement &element) -> cpl::Result<std::vector<DerElement> > {
                    return DerSplit(element.content, element.contentSize);
                };
                // Skipped elements must still be well-formed DER. A primitive element is
                // well-formed when its header is (the reader has checked it): its content octets
                // are not elements, and reading them as elements would reject valid identifiers.
                const auto isWellFormed = [](const DerElement &element) -> bool {
                    if ((element.tag & 0x20) == 0) {
                        return true;
                    }
                    return DerIsWellFormed(element.content, element.contentSize, DerMaxDepth);
                };

                // TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
                //   issuer, validity, subject, subjectPublicKeyInfo, [1] OPTIONAL, [2] OPTIONAL,
                //   [3] OPTIONAL }
                if (tbsCertificate.tag != TagSequence) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 tbs certificate is not a sequence" CPL_FILE_AND_LINE);
                }
                const auto tbs = splitOf(tbsCertificate);
                if (!tbs) {
                    return cpl::Err(tbs.error());
                }
                const size_t count = tbs->size();
                size_t position = 0;
                // The next element must exist and carry the given tag.
                const auto expect = [&](const uint8_t tag) -> const DerElement * {
                    if (position >= count || (*tbs)[position].tag != tag) {
                        return nullptr;
                    }
                    return &(*tbs)[position++];
                };
                // Rejects the element that expect() did not find.
                const auto rejectMissing = [&](const char *what) -> cpl::Err {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        std::string("[X] cert: rule R2 tbs certificate ") + what
                                            + " is missing or has the wrong tag " CPL_FILE_AND_LINE);
                };
                // Rejects an element whose content is not well-formed DER.
                const auto rejectMalformed = [&](const char *what) -> cpl::Err {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        std::string("[X] cert: rule R2 tbs certificate ") + what
                                            + " is not well-formed der " CPL_FILE_AND_LINE);
                };

                // version [0] EXPLICIT INTEGER DEFAULT v1
                const DerElement *version = nullptr;
                if (position < count && (*tbs)[position].tag == TagVersion) {
                    version = &(*tbs)[position++];
                }
                if (version != nullptr) {
                    const auto versionItems = splitOf(*version);
                    if (!versionItems) {
                        return cpl::Err(versionItems.error());
                    }
                    if (versionItems->size() != 1 || (*versionItems)[0].tag != TagInteger) {
                        return cpl::MakeErr(RuleViolatedBase + 2,
                                            "[X] cert: rule R2 tbs certificate version is not a single integer"
                                            CPL_FILE_AND_LINE);
                    }
                }

                const DerElement *serialNumber = expect(TagInteger);
                if (serialNumber == nullptr) {
                    return rejectMissing("serial number");
                }
                if (serialNumber->contentSize == 0) {
                    return rejectMalformed("serial number");
                }
                const DerElement *tbsSignature = expect(TagSequence);
                if (tbsSignature == nullptr) {
                    return rejectMissing("signature algorithm");
                }
                if (!isWellFormed(*tbsSignature)) {
                    return rejectMalformed("signature algorithm");
                }
                const DerElement *issuer = expect(TagSequence);
                if (issuer == nullptr) {
                    return rejectMissing("issuer");
                }
                if (!isWellFormed(*issuer)) {
                    return rejectMalformed("issuer");
                }

                // validity ::= SEQUENCE { notBefore Time, notAfter Time }
                const DerElement *validity = expect(TagSequence);
                if (validity == nullptr) {
                    return rejectMissing("validity");
                }
                const auto times = splitOf(*validity);
                if (!times) {
                    return cpl::Err(times.error());
                }
                if (times->size() != 2) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 tbs certificate validity does not have two times"
                                        CPL_FILE_AND_LINE);
                }
                if (!ParseX509Time((*times)[0], &out.notBefore)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 tbs certificate notBefore is not a utc or generalized time"
                                        CPL_FILE_AND_LINE);
                }
                if (!ParseX509Time((*times)[1], &out.notAfter)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 tbs certificate notAfter is not a utc or generalized time"
                                        CPL_FILE_AND_LINE);
                }

                const DerElement *subject = expect(TagSequence);
                if (subject == nullptr) {
                    return rejectMissing("subject");
                }
                if (!isWellFormed(*subject)) {
                    return rejectMalformed("subject");
                }

                // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
                const DerElement *subjectPublicKeyInfo = expect(TagSequence);
                if (subjectPublicKeyInfo == nullptr) {
                    return rejectMissing("subject public key info");
                }
                const auto spki = splitOf(*subjectPublicKeyInfo);
                if (!spki) {
                    return cpl::Err(spki.error());
                }
                if (spki->size() != 2) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 subject public key info does not have two elements"
                                        CPL_FILE_AND_LINE);
                }
                const DerElement &spkiAlgorithm = (*spki)[0];
                if (spkiAlgorithm.tag != TagSequence || !isWellFormed(spkiAlgorithm)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 subject public key algorithm is not a well-formed sequence"
                                        CPL_FILE_AND_LINE);
                }
                const DerElement &subjectPublicKey = (*spki)[1];
                if (subjectPublicKey.tag != TagBitString) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 subject public key is not a bit string" CPL_FILE_AND_LINE);
                }
                const uint8_t *keyOctets = nullptr;
                size_t keySize = 0;
                if (!DerBitStringOctets(subjectPublicKey, &keyOctets, &keySize)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 subject public key bit string is empty or has unused bits"
                                        CPL_FILE_AND_LINE);
                }
                // The subject public key must have the size of an Ed25519 key. The decision waits
                // until the structural checks of R2 are complete: a key of another size is the
                // consequence of another algorithm, and another algorithm violates R3.
                const bool keySizeOk = keySize == PublicKeyBytes;

                // issuerUniqueID [1], subjectUniqueID [2], extensions [3]: optional, each at
                // most once and in this order.
                const uint8_t optionalTags[] = {TagIssuerUniqueId, TagSubjectUniqueId, TagExtensions};
                for (size_t i = 0; i < sizeof(optionalTags) / sizeof(optionalTags[0]); i++) {
                    if (position < count && (*tbs)[position].tag == optionalTags[i]) {
                        if (!isWellFormed((*tbs)[position])) {
                            return rejectMalformed("optional element");
                        }
                        ++position;
                    }
                }
                if (position != count) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 tbs certificate has an unexpected element" CPL_FILE_AND_LINE);
                }

                // signatureValue ::= BIT STRING. Its length is not fixed here (it must be an
                // Ed25519 signature of 64 bytes, which R4 checks): a caller may still want to
                // inspect a certificate that fails that rule.
                if (signatureValue.tag != TagBitString) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 signature value is not a bit string" CPL_FILE_AND_LINE);
                }
                const uint8_t *signatureOctets = nullptr;
                size_t signatureSize = 0;
                if (!DerBitStringOctets(signatureValue, &signatureOctets, &signatureSize)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 signature value bit string is empty or has unused bits"
                                        CPL_FILE_AND_LINE);
                }
                // signatureAlgorithm is an AlgorithmIdentifier: a SEQUENCE.
                if (signatureAlgorithm.tag != TagSequence || !isWellFormed(signatureAlgorithm)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 signature algorithm is not a well-formed sequence"
                                        CPL_FILE_AND_LINE);
                }
                if (!keySizeOk) {
                    if (!IsEd25519Algorithm(spkiAlgorithm)) {
                        return cpl::MakeErr(RuleViolatedBase + 3,
                                            "[X] cert: rule R3 subject public key algorithm is not ed25519"
                                            CPL_FILE_AND_LINE);
                    }
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 subject public key is not 32 bytes" CPL_FILE_AND_LINE);
                }

                // R3: Ed25519 in all three places.
                if (!IsEd25519Algorithm(*tbsSignature)) {
                    return cpl::MakeErr(RuleViolatedBase + 3,
                                        "[X] cert: rule R3 tbs certificate signature algorithm is not ed25519"
                                        CPL_FILE_AND_LINE);
                }
                if (!IsEd25519Algorithm(signatureAlgorithm)) {
                    return cpl::MakeErr(RuleViolatedBase + 3,
                                        "[X] cert: rule R3 certificate signature algorithm is not ed25519"
                                        CPL_FILE_AND_LINE);
                }
                if (!IsEd25519Algorithm(spkiAlgorithm)) {
                    return cpl::MakeErr(RuleViolatedBase + 3,
                                        "[X] cert: rule R3 subject public key algorithm is not ed25519"
                                        CPL_FILE_AND_LINE);
                }

                out.tbs.assign(tbsCertificate.start, tbsCertificate.start + tbsCertificate.totalSize);
                out.signature.assign(signatureOctets, signatureOctets + signatureSize);
                std::memcpy(out.publicKey.data(), keyOctets, out.publicKey.size());
                return out;
            }

            // now >= moment - 86400, without an overflow when moment is close to INT64_MIN.
            inline bool IsWithinDayBefore(const int64_t now, const int64_t moment) {
                if (moment < INT64_MIN + GraceSeconds) {
                    return true;
                }
                return now >= moment - GraceSeconds;
            }

            // R4.
            inline cpl::Int32Result VerifyCertificateSignature(const Certificate &cert,
                                                              const uint8_t issuerPublicKey[32]) {
                if (cert.tbs.empty() || cert.signature.size() != SignatureBytes) {
                    return cpl::MakeErr(RuleViolatedBase + 4,
                                        "[X] cert: rule R4 certificate signature is not 64 bytes" CPL_FILE_AND_LINE);
                }
                const int verified = naion_sign_ed25519_verify_detached(
                    cert.signature.data(),
                    cert.tbs.data(),
                    static_cast<unsigned long long>(cert.tbs.size()),
                    issuerPublicKey
                );
                if (verified != 0) {
                    return cpl::MakeErr(RuleViolatedBase + 4,
                                        "[X] cert: rule R4 certificate signature verify failed" CPL_FILE_AND_LINE);
                }
                return 0;
            }

            // Decodes base64url (RFC 4648 section 5) without padding into a byte string. The
            // input must be canonical: only the 64 characters of the alphabet, a length that
            // is not 1 modulo 4, and zero bits after the last octet. Nothing else decodes, so
            // every byte string has exactly one text form.
            inline int Base64UrlValue(const char c) {
                if (c >= 'A' && c <= 'Z') {
                    return c - 'A';
                }
                if (c >= 'a' && c <= 'z') {
                    return c - 'a' + 26;
                }
                if (c >= '0' && c <= '9') {
                    return c - '0' + 52;
                }
                if (c == '-') {
                    return 62;
                }
                if (c == '_') {
                    return 63;
                }
                return -1;
            }

            inline bool Base64UrlDecode(const std::string &text, std::string &out) {
                out.clear();
                if (text.size() % 4 == 1) {
                    return false;
                }
                uint32_t accumulator = 0;
                unsigned int pendingBits = 0;
                for (size_t i = 0; i < text.size(); i++) {
                    const int value = Base64UrlValue(text[i]);
                    if (value < 0) {
                        out.clear();
                        return false;
                    }
                    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
                    pendingBits += 6;
                    if (pendingBits >= 8) {
                        pendingBits -= 8;
                        out.push_back(static_cast<char>((accumulator >> pendingBits) & 0xFF));
                    }
                }
                // The bits of the last character that do not belong to an octet must be zero.
                if (pendingBits > 0 && (accumulator & ((1u << pendingBits) - 1u)) != 0) {
                    out.clear();
                    return false;
                }
                return true;
            }

            // Parses text as a JSON object. The json library is asked not to throw, and an
            // exception that it throws anyway is caught here: nothing leaves this module.
            inline cpl::Int32Result ParseJsonObject(const std::string &text, const char *what, nlohmann::json &out) {
                try {
                    auto parsed = nlohmann::json::parse(text, nullptr, false);
                    if (parsed.is_discarded()) {
                        return cpl::MakeErr(RuleViolatedBase + 1,
                                            std::string("[X] cert: rule R1 jwt ") + what + " is not valid json"
                                            CPL_FILE_AND_LINE);
                    }
                    if (!parsed.is_object()) {
                        return cpl::MakeErr(RuleViolatedBase + 1,
                                            std::string("[X] cert: rule R1 jwt ") + what + " is not a json object"
                                            CPL_FILE_AND_LINE);
                    }
                    out = std::move(parsed);
                    return 0;
                } catch (...) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        std::string("[X] cert: rule R1 jwt ") + what + " json parsing raised an exception"
                                        CPL_FILE_AND_LINE);
                }
            }

            // Reads an integer member of a JSON object. Floats, booleans, strings and values
            // outside the range of int64_t are not integers for R1.
            inline bool GetJsonInteger(const nlohmann::json &object, const char *name, int64_t *out) {
                const auto member = object.find(name);
                if (member == object.end() || !member->is_number_integer()) {
                    return false;
                }
                if (member->is_number_unsigned()) {
                    const uint64_t value = member->get<uint64_t>();
                    if (value > static_cast<uint64_t>(INT64_MAX)) {
                        return false;
                    }
                    *out = static_cast<int64_t>(value);
                    return true;
                }
                *out = member->get<int64_t>();
                return true;
            }

            // Worker of VerifyConfigJwt. enforceTime selects whether R5 and R8 are applied.
            inline cpl::Result<VerifiedJwt> VerifyConfigJwtRules(const std::string &jwt, const uint8_t rootPublicKey[32],
                                                                const int64_t nowUnix, const bool enforceTime) {
                // R1: exactly three segments.
                const size_t firstDot = jwt.find('.');
                const size_t secondDot = firstDot == std::string::npos ? std::string::npos : jwt.find('.', firstDot + 1);
                if (firstDot == std::string::npos || secondDot == std::string::npos
                    || jwt.find('.', secondDot + 1) != std::string::npos) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt does not have exactly three segments" CPL_FILE_AND_LINE);
                }
                const std::string headerText = jwt.substr(0, firstDot);
                const std::string payloadText = jwt.substr(firstDot + 1, secondDot - firstDot - 1);
                const std::string signatureText = jwt.substr(secondDot + 1);

                // The header and the payload have to be decoded before R1 can look into them.
                // A segment that does not decode is reported as R2: it is the root cause.
                std::string headerJson;
                std::string payloadJson;
                if (!Base64UrlDecode(headerText, headerJson)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 jwt header segment is not valid base64url"
                                        CPL_FILE_AND_LINE);
                }
                if (!Base64UrlDecode(payloadText, payloadJson)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 jwt payload segment is not valid base64url"
                                        CPL_FILE_AND_LINE);
                }

                // R1: header.
                nlohmann::json header;
                const auto headerParsed = ParseJsonObject(headerJson, "header", header);
                if (!headerParsed) {
                    return cpl::Err(headerParsed.error());
                }
                const auto alg = header.find("alg");
                if (alg == header.end() || !alg->is_string() || alg->get<std::string>() != "EdDSA") {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt header alg is not EdDSA" CPL_FILE_AND_LINE);
                }
                const auto x5c = header.find("x5c");
                if (x5c == header.end() || !x5c->is_array() || x5c->size() != 1 || !(*x5c)[0].is_string()) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt header x5c is not an array with exactly one string"
                                        CPL_FILE_AND_LINE);
                }

                // R1: payload.
                nlohmann::json payload;
                const auto payloadParsed = ParseJsonObject(payloadJson, "payload", payload);
                if (!payloadParsed) {
                    return cpl::Err(payloadParsed.error());
                }
                const auto group = payload.find("group");
                if (group == payload.end() || !group->is_string()) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt payload group is not a string" CPL_FILE_AND_LINE);
                }
                VerifiedJwt out{};
                if (!GetJsonInteger(payload, "serial", &out.serial)) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt payload serial is not an integer" CPL_FILE_AND_LINE);
                }
                int64_t issuedAt = 0;
                int64_t expiresAt = 0;
                if (!GetJsonInteger(payload, "iat", &issuedAt)) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt payload iat is not an integer" CPL_FILE_AND_LINE);
                }
                if (!GetJsonInteger(payload, "exp", &expiresAt)) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt payload exp is not an integer" CPL_FILE_AND_LINE);
                }
                const auto config = payload.find("config");
                if (config == payload.end() || !config->is_object()) {
                    return cpl::MakeErr(RuleViolatedBase + 1,
                                        "[X] cert: rule R1 jwt payload config is not an object" CPL_FILE_AND_LINE);
                }

                // R2: the remaining base64url segments and the certificate.
                std::string signature;
                if (!Base64UrlDecode(signatureText, signature)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 jwt signature segment is not valid base64url"
                                        CPL_FILE_AND_LINE);
                }
                const std::string certificateText = (*x5c)[0].get<std::string>();
                std::string certificateDer;
                if (!Base64UrlDecode(certificateText, certificateDer)) {
                    return cpl::MakeErr(RuleViolatedBase + 2,
                                        "[X] cert: rule R2 jwt x5c certificate is not valid base64url"
                                        CPL_FILE_AND_LINE);
                }
                const auto certificate = ParseCertificateRules(
                    reinterpret_cast<const uint8_t *>(certificateDer.data()),
                    certificateDer.size()
                );
                if (!certificate) {
                    return cpl::Err(certificate.error());
                }

                // R4.
                const auto issued = VerifyCertificateSignature(*certificate, rootPublicKey);
                if (!issued) {
                    return cpl::Err(issued.error());
                }

                // R5.
                if (enforceTime) {
                    if (!IsWithinDayBefore(nowUnix, certificate->notBefore)) {
                        return cpl::MakeErr(RuleViolatedBase + 5,
                                            "[X] cert: rule R5 jwt certificate is not yet valid" CPL_FILE_AND_LINE);
                    }
                    if (nowUnix > certificate->notAfter) {
                        return cpl::MakeErr(RuleViolatedBase + 5,
                                            "[X] cert: rule R5 jwt certificate is expired" CPL_FILE_AND_LINE);
                    }
                }

                // R6: the signature covers the original text "header_b64.payload_b64".
                if (signature.size() != SignatureBytes) {
                    return cpl::MakeErr(RuleViolatedBase + 6,
                                        "[X] cert: rule R6 jwt signature is not 64 bytes" CPL_FILE_AND_LINE);
                }
                const int verified = naion_sign_ed25519_verify_detached(
                    reinterpret_cast<const uint8_t *>(signature.data()),
                    reinterpret_cast<const uint8_t *>(jwt.data()),
                    static_cast<unsigned long long>(secondDot),
                    certificate->publicKey.data()
                );
                if (verified != 0) {
                    return cpl::MakeErr(RuleViolatedBase + 6,
                                        "[X] cert: rule R6 jwt signature verify failed" CPL_FILE_AND_LINE);
                }

                // R8.
                if (enforceTime) {
                    if (!IsWithinDayBefore(nowUnix, issuedAt)) {
                        return cpl::MakeErr(RuleViolatedBase + 8,
                                            "[X] cert: rule R8 jwt is not yet valid" CPL_FILE_AND_LINE);
                    }
                    if (nowUnix > expiresAt) {
                        return cpl::MakeErr(RuleViolatedBase + 8,
                                            "[X] cert: rule R8 jwt is expired" CPL_FILE_AND_LINE);
                    }
                }

                out.payloadJson = std::move(payloadJson);
                out.group = group->get<std::string>();
                return out;
            }
        }

        // R2 + R3. Parses one X.509 certificate in DER form.
        //
        // The certificate must be a SEQUENCE of exactly three elements (tbsCertificate,
        // signatureAlgorithm, signatureValue), the elements of tbsCertificate must follow the
        // template in the order of RFC 5280, every BIT STRING must have a whole number of
        // octets, and all three algorithm identifiers must be Ed25519 (1.3.101.112) without
        // parameters. The DER reader accepts the short and the long form of the length (up to
        // four octets) and rejects the indefinite form, over-long forms, truncated elements,
        // the high tag number form and trailing garbage after the certificate.
        //
        // A failure is reported with CertParseError; the reason names R2 (not valid DER or not
        // of the template) or R3 (not an Ed25519 certificate). The signature itself is not
        // verified here: use VerifyIssuedBy.
        inline cpl::Result<Certificate> ParseCertificate(const uint8_t *der, const size_t size) {
            try {
                auto parsed = impl::ParseCertificateRules(der, size);
                if (!parsed) {
                    return cpl::MakeErr(CertParseError, parsed.error().Reason);
                }
                return parsed;
            } catch (...) {
                return cpl::MakeErr(cpl::Error::OutOfMemory,
                                    "[X] cert: rule R2 certificate parsing ran out of memory" CPL_FILE_AND_LINE);
            }
        }

        // R4 + R5. Checks that the certificate is signed by the owner of issuerPublicKey
        // and is valid at nowUnix.
        //
        //   R4  signatureValue is 64 bytes and verifies with issuerPublicKey over tbsCertificate
        //   R5  notBefore - 86400 <= nowUnix <= notAfter
        //
        // Returns 0 or the error of the first violated rule (RuleViolatedBase + 4 or + 5).
        inline cpl::Int32Result VerifyIssuedBy(const Certificate &cert, const uint8_t issuerPublicKey[32],
                                               const int64_t nowUnix) {
            if (issuerPublicKey == nullptr) {
                return cpl::MakeErr(cpl::Error::NullPointer,
                                    "[X] cert: issuer public key is null" CPL_FILE_AND_LINE);
            }
            try {
                const auto issued = impl::VerifyCertificateSignature(cert, issuerPublicKey);
                if (!issued) {
                    return cpl::Err(issued.error());
                }
                if (!impl::IsWithinDayBefore(nowUnix, cert.notBefore)) {
                    return cpl::MakeErr(RuleViolatedBase + 5,
                                        "[X] cert: rule R5 certificate is not yet valid" CPL_FILE_AND_LINE);
                }
                if (nowUnix > cert.notAfter) {
                    return cpl::MakeErr(RuleViolatedBase + 5,
                                        "[X] cert: rule R5 certificate is expired" CPL_FILE_AND_LINE);
                }
                return 0;
            } catch (...) {
                return cpl::MakeErr(cpl::Error::OutOfMemory,
                                    "[X] cert: rule R4 certificate verification ran out of memory" CPL_FILE_AND_LINE);
            }
        }

        // R1..R6 and R8, in this order. The first violated rule is reported with
        // RuleViolatedBase + <rule number>; on success the decoded payload is returned.
        //
        //   R1  jwt has exactly three segments; the header is a JSON object whose alg is
        //       "EdDSA" and whose x5c is an array with exactly one string; the payload is a
        //       JSON object with group (string), serial, iat, exp (integers) and config (object)
        //   R2  the header, payload, signature and x5c[0] segments are canonical base64url and
        //       x5c[0] is a certificate that passes ParseCertificate
        //   R3  the certificate is an Ed25519 certificate (reported by the parser of R2)
        //   R4  the certificate is signed by rootPublicKey
        //   R5  notBefore - 86400 <= nowUnix <= notAfter                   (EnforceTime only)
        //   R6  the signature segment is 64 bytes and verifies with the public key of the
        //       certificate over the original text "header_b64.payload_b64"
        //   R8  iat - 86400 <= nowUnix <= exp                                (EnforceTime only)
        //
        // A header or payload segment that does not decode is reported as R2 although it is
        // read while R1 is checked: the undecodable segment is the root cause of the failure.
        //
        // check is an int32_t because the header is shared with C-style callers: every value
        // other than SkipTime enforces the time rules.
        inline cpl::Result<VerifiedJwt> VerifyConfigJwt(const std::string &jwt, const uint8_t rootPublicKey[32],
                                                       const int64_t nowUnix, const int32_t check = EnforceTime) {
            if (rootPublicKey == nullptr) {
                return cpl::MakeErr(cpl::Error::NullPointer,
                                    "[X] cert: root public key is null" CPL_FILE_AND_LINE);
            }
            try {
                return impl::VerifyConfigJwtRules(jwt, rootPublicKey, nowUnix, check != SkipTime);
            } catch (...) {
                return cpl::MakeErr(cpl::Error::OutOfMemory,
                                    "[X] cert: rule R1 jwt parsing ran out of memory" CPL_FILE_AND_LINE);
            }
        }
    }
}

#endif // CPL_CERT_HPP_ORBIT_LANTERN_MODERN_CAPTURE_SEASON_GLACIER_TEXTBOOK_PICNIC_CREDIT
