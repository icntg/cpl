// Tests for cpl::cert - Ed25519 certificate chain and configuration jwt verification.
//
// The fixed vectors come from test/cert_vectors.inc, which test/gen_cert_vectors.go prints:
// every key is derived from a fixed seed and every token is signed the way the server signs
// it, so a rejection vector violates exactly the rule that its comment names.
//
// Tokens that are rejected before any signature is checked are also built here at runtime,
// by editing the text of kValidJwt. Certificates with a chosen defect are assembled from
// their elements, because ParseCertificate does not verify the signature.
#include "../vendor/doctest/doctest.hpp"
// The library headers and the json header come first with their own warnings: cert.hpp is
// clean under -Wall -Wextra, so it must not add a warning to the ones below.
#include "../base.hpp"
#include "../naion.hpp"
#include "../vendor/nlohmann/json/json.hpp"
#include "../cert.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace {
#include "cert_vectors.inc"
}

using namespace cpl;
using namespace cpl::cert;

namespace {
    // Used by the helpers below; defined further down.
    static std::vector<std::string> SplitToken(const std::string &token);
    static std::string LibraryDecode(const std::string &segment);

    // ---- Results ---------------------------------------------------------------------------

    // Unpacks a Result that must hold a value.
    template <typename T>
    static T Must(Result<T> r) {
        if (!r.has_value()) {
            const std::string reason = r.error().Reason;
            FAIL("the call failed: ", reason);
        }
        return std::move(r.value());
    }

    // Checks that r is the error of a rule: the code is RuleViolatedBase + rule, the reason
    // starts with "[X] cert: ", names the rule and ends with the location of the failing
    // check in cert.hpp. Returns the error.
    template <typename T>
    static cpl::Error ExpectRule(Result<T> r, const int rule) {
        REQUIRE_FALSE(r.has_value());
        const cpl::Error error = r.error();
        const std::string marker = std::string("rule R") + std::to_string(rule) + " ";
        CHECK_MESSAGE(error.Code.i64 == RuleViolatedBase + rule, error.Reason);
        CHECK_MESSAGE(error.Reason.rfind("[X] cert: ", 0) == 0, error.Reason);
        CHECK_MESSAGE(error.Reason.find(marker) != std::string::npos, error.Reason << " does not name " << marker);
        CHECK_MESSAGE(error.Reason.find("cert.hpp:") != std::string::npos, error.Reason);
        const bool nonEmpty = !error.Reason.empty();
        const bool endsWithLocation = nonEmpty && error.Reason.back() == '>';
        CHECK_MESSAGE(endsWithLocation, error.Reason);
        return error;
    }

    // Checks that VerifyConfigJwt rejects the token at kFixedNow with the rule.
    static cpl::Error ExpectJwtRule(const std::string &token, const int rule, const int32_t check = EnforceTime) {
        return ExpectRule(VerifyConfigJwt(token, kRootPublicKey, kFixedNow, check), rule);
    }

    // The same at another time.
    static cpl::Error ExpectJwtRuleAt(const std::string &token, const int rule, const int64_t now) {
        return ExpectRule(VerifyConfigJwt(token, kRootPublicKey, now), rule);
    }

    // Checks that VerifyConfigJwt accepts the token at kFixedNow and returns its decoded
    // payload: the group, the serial and the text of the second segment of the token.
    static void ExpectAccepted(const std::string &token, const int32_t check = EnforceTime) {
        const auto verified = Must(VerifyConfigJwt(token, kRootPublicKey, kFixedNow, check));
        CHECK_MESSAGE(verified.group == "default", verified.group);
        CHECK_MESSAGE(verified.serial == kValidSerial, verified.serial);
        CHECK(verified.payloadJson == LibraryDecode(SplitToken(token)[1]));
    }

    // The same at another time.
    static void ExpectAcceptedAt(const std::string &token, const int64_t now) {
        const auto verified = Must(VerifyConfigJwt(token, kRootPublicKey, now));
        CHECK_MESSAGE(verified.serial == kValidSerial, verified.serial);
        CHECK(verified.payloadJson == LibraryDecode(SplitToken(token)[1]));
    }

    // ---- Base64url and token text ----------------------------------------------------------

    static std::vector<std::string> SplitToken(const std::string &token) {
        return cpl::strings::Split(token, ".");
    }

    static std::string JoinToken(const std::vector<std::string> &segments) {
        std::string token{};
        for (size_t i = 0; i < segments.size(); i++) {
            if (i > 0) {
                token += '.';
            }
            token += segments[i];
        }
        return token;
    }

    // Decodes with the base64url decoder of the library, the reference for canonical text.
    static std::string LibraryDecode(const std::string &segment) {
        const auto bytes = Must(cpl::codec::Base64::UrlSafeBase64Decode(segment.c_str()));
        return std::string(bytes.begin(), bytes.end());
    }

    // Encodes with the base64url encoder of the library. The encoder rejects empty input.
    static std::string LibraryEncode(const std::string &text) {
        if (text.empty()) {
            return "";
        }
        const Stream bytes(text.begin(), text.end());
        return Must(cpl::codec::Base64::UrlSafeBase64Encode(bytes));
    }

    static const char *const kBase64UrlAlphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Replaces the character at position.
    static std::string ReplaceAt(std::string text, const size_t position, const char replacement) {
        text.at(position) = replacement;
        return text;
    }

    // Replaces the character at position by a different character of the alphabet.
    static std::string FlipAt(std::string text, const size_t position) {
        text.at(position) = text[position] == 'A' ? 'B' : 'A';
        return text;
    }

    // Appends characters until the length is 1 modulo 4. No base64url text has such a length.
    static std::string PadToRemainderOne(std::string segment) {
        while (segment.size() % 4 != 1) {
            segment += 'A';
        }
        return segment;
    }

    // The same octets as segment, but written with a last character whose unused bits are not
    // zero. It decodes to the same bytes; it is not the canonical text of those bytes.
    static std::string NonCanonical(std::string segment) {
        // Two characters hold twelve bits: eight bits of an octet and four unused bits.
        while (segment.size() % 4 != 2) {
            segment += 'A';
        }
        const std::string alphabet(kBase64UrlAlphabet);
        const size_t value = alphabet.find(segment.back());
        segment.back() = alphabet[value | 1];
        return segment;
    }

    static std::string ReplaceOnce(std::string text, const std::string &from, const std::string &to) {
        const size_t position = text.find(from);
        REQUIRE(position != std::string::npos);
        return text.replace(position, from.size(), to);
    }

    // ---- JSON of the valid token -----------------------------------------------------------

    static nlohmann::json ParseJson(const std::string &text) {
        return nlohmann::json::parse(text);
    }

    static std::string Dump(const nlohmann::json &value) {
        return value.dump();
    }

    static nlohmann::json ValidHeader() {
        return ParseJson(LibraryDecode(SplitToken(kValidJwt)[0]));
    }

    static nlohmann::json ValidPayload() {
        return ParseJson(LibraryDecode(SplitToken(kValidJwt)[1]));
    }

    // A token with the signature segment of kValidJwt. Such a token can never pass R6: a rule
    // before R6 has to reject it.
    static std::string Token(const std::string &headerText, const std::string &payloadText) {
        return LibraryEncode(headerText) + "." + LibraryEncode(payloadText) + "." + SplitToken(kValidJwt)[2];
    }

    static std::string Token(const nlohmann::json &header, const nlohmann::json &payload) {
        return Token(header.dump(), payload.dump());
    }

    // A copy of the object with the member set.
    template <typename T>
    static nlohmann::json With(nlohmann::json object, const char *key, const T &value) {
        object[key] = value;
        return object;
    }

    // A copy of the object without the member.
    static nlohmann::json Without(nlohmann::json object, const char *key) {
        object.erase(key);
        return object;
    }

    // ---- DER building ----------------------------------------------------------------------

    static std::vector<uint8_t> Bytes(const std::initializer_list<int> values) {
        std::vector<uint8_t> out{};
        for (const int value : values) {
            out.push_back(static_cast<uint8_t>(value));
        }
        return out;
    }

    static std::vector<uint8_t> Text(const std::string &text) {
        return std::vector<uint8_t>(text.begin(), text.end());
    }

    static std::vector<uint8_t> ToVector(const uint8_t *data, const size_t size) {
        return std::vector<uint8_t>(data, data + size);
    }

    static std::vector<uint8_t> Cat(const std::initializer_list<std::vector<uint8_t> > parts) {
        std::vector<uint8_t> out{};
        for (const auto &part : parts) {
            out.insert(out.end(), part.begin(), part.end());
        }
        return out;
    }

    // One element from its identifier octet and its content octets (up to three length octets).
    static std::vector<uint8_t> Tlv(const uint8_t tag, const std::vector<uint8_t> &content) {
        std::vector<uint8_t> out{};
        out.push_back(tag);
        if (content.size() < 0x80) {
            out.push_back(static_cast<uint8_t>(content.size()));
        } else if (content.size() < 0x100) {
            out.push_back(0x81);
            out.push_back(static_cast<uint8_t>(content.size()));
        } else if (content.size() < 0x10000) {
            out.push_back(0x82);
            out.push_back(static_cast<uint8_t>(content.size() >> 8));
            out.push_back(static_cast<uint8_t>(content.size()));
        } else {
            out.push_back(0x83);
            out.push_back(static_cast<uint8_t>(content.size() >> 16));
            out.push_back(static_cast<uint8_t>(content.size() >> 8));
            out.push_back(static_cast<uint8_t>(content.size()));
        }
        out.insert(out.end(), content.begin(), content.end());
        return out;
    }

    static std::vector<uint8_t> Seq(const std::initializer_list<std::vector<uint8_t> > parts) {
        return Tlv(0x30, Cat(parts));
    }

    // An X.509 Time element with the given identifier octet.
    static std::vector<uint8_t> Time(const uint8_t tag, const std::string &text) {
        return Tlv(tag, Text(text));
    }

    static std::vector<uint8_t> UtcTime(const std::string &text) {
        return Time(0x17, text);
    }

    static std::vector<uint8_t> GeneralizedTime(const std::string &text) {
        return Time(0x18, text);
    }

    // A BIT STRING whose value is a whole number of octets.
    static std::vector<uint8_t> BitString(const std::vector<uint8_t> &octets) {
        return Tlv(0x03, Cat({Bytes({0x00}), octets}));
    }

    // A Name with one common name: SEQUENCE OF SET OF SEQUENCE { OID 2.5.4.3, UTF8String }.
    static std::vector<uint8_t> Name(const std::string &commonName) {
        const std::vector<uint8_t> attribute = Seq({
            Bytes({0x06, 0x03, 0x55, 0x04, 0x03}),
            Tlv(0x13, Text(commonName)),
        });
        return Seq({Tlv(0x31, attribute)});
    }

    // Algorithm identifiers.
    static std::vector<uint8_t> Ed25519Algorithm() {
        return Bytes({0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70});
    }

    static std::vector<uint8_t> Ed25519WithNull() {
        return Bytes({0x30, 0x07, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x05, 0x00});
    }

    static std::vector<uint8_t> EcdsaWithSha256() {
        return Seq({
            Bytes({0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}),
            Bytes({0x05, 0x00}),
        });
    }

    static std::vector<uint8_t> EcP256Algorithm() {
        return Seq({
            Bytes({0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}),
            Bytes({0x05, 0x00}),
        });
    }

    static std::vector<uint8_t> KeyBytes() {
        return ToVector(kValidCertPublicKey, sizeof(kValidCertPublicKey));
    }

    // A certificate assembled from its elements; the defaults have the shape of kValidCert.
    // An empty element is left out, so clearing a field removes it from the certificate.
    struct SyntheticCertificate {
        std::vector<uint8_t> version = Tlv(0xA0, Bytes({0x02, 0x01, 0x02}));
        std::vector<uint8_t> serialNumber = Bytes({0x02, 0x02, 0x01, 0x00});
        std::vector<uint8_t> tbsSignature = Ed25519Algorithm();
        std::vector<uint8_t> issuer = Name("cpl-test-root");
        std::vector<uint8_t> validity = Seq({UtcTime("260601000000Z"), UtcTime("280601000000Z")});
        std::vector<uint8_t> subject = Name("cpl-test-valid-intermediate");
        std::vector<uint8_t> subjectPublicKeyInfo = Seq({Ed25519Algorithm(), BitString(KeyBytes())});
        std::vector<uint8_t> issuerUniqueId;  // [1], absent
        std::vector<uint8_t> subjectUniqueId; // [2], absent
        std::vector<uint8_t> extensions = Tlv(0xA3, Seq({Bytes({0x30, 0x00})}));
        std::vector<uint8_t> signatureAlgorithm = Ed25519Algorithm();
        std::vector<uint8_t> signatureValue = BitString(std::vector<uint8_t>(64, 0x5A));

        // The content octets of tbsCertificate, without the empty elements.
        std::vector<uint8_t> Fields() const {
            const std::vector<uint8_t> *const fields[] = {
                &this->version,           &this->serialNumber,        &this->tbsSignature,
                &this->issuer,            &this->validity,            &this->subject,
                &this->subjectPublicKeyInfo, &this->issuerUniqueId,   &this->subjectUniqueId,
                &this->extensions,
            };
            std::vector<uint8_t> content{};
            for (const auto *field : fields) {
                if (!field->empty()) {
                    content.insert(content.end(), field->begin(), field->end());
                }
            }
            return content;
        }

        std::vector<uint8_t> Tbs() const {
            return Tlv(0x30, this->Fields());
        }

        // SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        std::vector<uint8_t> Build() const {
            return Seq({this->Tbs(), this->signatureAlgorithm, this->signatureValue});
        }
    };

    // The number of identifier and length octets of the element at the start of der.
    static size_t HeaderSize(const uint8_t *der) {
        return (der[1] & 0x80) == 0 ? 2 : 2 + (der[1] & 0x7F);
    }

    // The complete size of the element at the start of der.
    static size_t ElementSize(const uint8_t *der) {
        const size_t header = HeaderSize(der);
        size_t length = der[1] & 0x7F;
        if (header > 2) {
            length = 0;
            for (size_t i = 2; i < header; i++) {
                length = (length << 8) | der[i];
            }
        }
        return header + length;
    }

    // The element with its identifier and length octets replaced.
    static std::vector<uint8_t> WithHeader(const std::vector<uint8_t> &der,
                                           const std::vector<uint8_t> &header) {
        std::vector<uint8_t> out = header;
        out.insert(out.end(), der.begin() + static_cast<std::ptrdiff_t>(HeaderSize(der.data())), der.end());
        return out;
    }

    static Result<Certificate> ParseDer(const std::vector<uint8_t> &der) {
        return ParseCertificate(der.data(), der.size());
    }

    // Checks that ParseCertificate rejects der with CertParseError and names the rule.
    static void ExpectParseError(const std::vector<uint8_t> &der, const char *rule) {
        const auto parsed = ParseDer(der);
        REQUIRE_FALSE(parsed.has_value());
        const std::string reason = parsed.error().Reason;
        CHECK_MESSAGE(parsed.error().Code.i64 == CertParseError, reason);
        const std::string detail = reason + " does not name " + rule;
        CHECK_MESSAGE(reason.find(rule) != std::string::npos, detail);
    }

    // An independent reference for the conversion of a civil date into Unix seconds: it
    // counts the days year by year from 1970-01-01.
    static int64_t ReferenceUnix(const int year, const int month, const int day,
                                 const int hour, const int minute, const int second) {
        static const int monthLengths[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        const auto leap = [](const int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; };
        const auto yearLength = [&](const int y) { return leap(y) ? 366 : 365; };
        int64_t days = day - 1;
        for (int m = 0; m < month - 1; m++) {
            days += monthLengths[m] + (m == 1 && leap(year) ? 1 : 0);
        }
        if (year >= 1970) {
            for (int y = 1970; y < year; y++) {
                days += yearLength(y);
            }
        } else {
            for (int y = year; y < 1970; y++) {
                days -= yearLength(y);
            }
        }
        return days * 86400 + hour * 3600 + minute * 60 + second;
    }

}

TEST_SUITE("cpl::cert") {
    TEST_CASE("ParseCertificate returns the key, the validity and the signed parts of the valid intermediate") {
        const auto cert = Must(ParseCertificate(kValidCert, sizeof(kValidCert)));
        CHECK(std::memcmp(cert.publicKey.data(), kValidCertPublicKey, sizeof(kValidCertPublicKey)) == 0);
        CHECK_EQ(cert.notBefore, kValidCertNotBefore);
        CHECK_EQ(cert.notAfter, kValidCertNotAfter);

        // tbs is the complete first element of the certificate, signature the octets of the last.
        const size_t tbsOffset = HeaderSize(kValidCert);
        const size_t tbsSize = ElementSize(kValidCert + tbsOffset);
        CHECK_MESSAGE(cert.tbs.size() == tbsSize, cert.tbs.size() << " instead of " << tbsSize);
        CHECK(std::equal(cert.tbs.begin(), cert.tbs.end(), kValidCert + tbsOffset));
        CHECK_MESSAGE(cert.signature.size() == 64, cert.signature.size());
        CHECK(std::equal(cert.signature.begin(), cert.signature.end(), kValidCert + sizeof(kValidCert) - 64));
    }

    TEST_CASE("ParseCertificate returns the windows that the generator printed") {
        const auto expired = Must(ParseDer(ToVector(kExpiredCert, sizeof(kExpiredCert))));
        CHECK_EQ(expired.notBefore, kExpiredCertNotBefore);
        CHECK_EQ(expired.notAfter, kExpiredCertNotAfter);
        CHECK(expired.notAfter < kFixedNow);

        const auto notYetValid = Must(ParseDer(ToVector(kNotYetValidCert, sizeof(kNotYetValidCert))));
        CHECK_EQ(notYetValid.notBefore, kNotYetValidCertNotBefore);
        CHECK_EQ(notYetValid.notAfter, kNotYetValidCertNotAfter);
        CHECK(notYetValid.notBefore > kFixedNow + 86400);

        // Go writes GeneralizedTime from 2050 on and UTCTime before, so this certificate has both.
        const auto generalized = Must(ParseDer(ToVector(kGeneralizedTimeCert, sizeof(kGeneralizedTimeCert))));
        CHECK_EQ(generalized.notBefore, kGeneralizedTimeCertNotBefore);
        CHECK_EQ(generalized.notAfter, kGeneralizedTimeCertNotAfter);
        CHECK_EQ(generalized.notAfter, ReferenceUnix(2055, 6, 1, 0, 0, 0));
    }

    TEST_CASE("ParseCertificate converts UTCTime and GeneralizedTime like an independent reference") {
        struct Form {
            uint8_t tag;
            const char *text;
            int year;
            int month;
            int day;
            int hour;
            int minute;
            int second;
        };
        const Form forms[] = {
            {0x17, "700101000000Z", 1970, 1, 1, 0, 0, 0},
            {0x17, "691231235959Z", 1969, 12, 31, 23, 59, 59},
            {0x17, "500101000000Z", 1950, 1, 1, 0, 0, 0},
            {0x17, "491231235959Z", 2049, 12, 31, 23, 59, 59},
            {0x17, "000229120000Z", 2000, 2, 29, 12, 0, 0},
            {0x17, "800229000000Z", 1980, 2, 29, 0, 0, 0},
            {0x17, "990701000000Z", 1999, 7, 1, 0, 0, 0},
            {0x18, "20260601000000Z", 2026, 6, 1, 0, 0, 0},
            {0x18, "20500101000000Z", 2050, 1, 1, 0, 0, 0},
            {0x18, "21000228000000Z", 2100, 2, 28, 0, 0, 0},
            {0x18, "24000229000000Z", 2400, 2, 29, 0, 0, 0},
            {0x18, "00000101000000Z", 0, 1, 1, 0, 0, 0},
            {0x18, "99991231235959Z", 9999, 12, 31, 23, 59, 59},
        };
        for (const auto &form : forms) {
            SyntheticCertificate certificate{};
            certificate.validity = Seq({Time(form.tag, form.text), GeneralizedTime("99991231235959Z")});
            const auto parsed = Must(ParseDer(certificate.Build()));
            const int64_t expected = ReferenceUnix(form.year, form.month, form.day, form.hour, form.minute,
                                                   form.second);
            CHECK_MESSAGE(parsed.notBefore == expected,
                          form.text << ": " << parsed.notBefore << " instead of " << expected);
        }
    }

    TEST_CASE("ParseCertificate rejects times that are not the two forms of RFC 5280") {
        const char *const texts[] = {
            "261300000000Z",        // month 13
            "260100000000Z",        // day 0
            "260631000000Z",        // June has 30 days
            "260229000000Z",        // 2026 is not a leap year
            "21000229000000Z",      // 2100 is not a leap year
            "19000229000000Z",      // 1900 is not a leap year
            "261201240000Z",        // hour 24
            "261201006000Z",        // minute 60
            "261201000060Z",        // second 60, the leap second that RFC 5280 does not allow
            "260601000000+0100",    // an offset instead of Z
            "2606010000Z",          // no seconds
            "20260601000000.000Z",  // fractions of a second
            "202606010000000Z",     // one digit too many
            "26A601000000Z",        // not a digit
            "260601000000z",        // lowercase
            " 60601000000Z",        // a space
            "",                     // nothing
        };
        for (const char *text : texts) {
            INFO(text);
            SyntheticCertificate certificate{};
            certificate.validity = Seq({UtcTime(text), UtcTime("280601000000Z")});
            ExpectParseError(certificate.Build(), "rule R2 tbs certificate notBefore");
            certificate.validity = Seq({UtcTime("260601000000Z"), GeneralizedTime(text)});
            ExpectParseError(certificate.Build(), "rule R2 tbs certificate notAfter");
        }
        // The right length with another identifier octet is not a Time either.
        SyntheticCertificate certificate{};
        certificate.validity = Seq({GeneralizedTime("260601000000Z"), Time(0x0C, "20260601000000Z")});
        ExpectParseError(certificate.Build(), "rule R2 tbs certificate notBefore");
    }

    TEST_CASE("ParseCertificate accepts the optional elements, also when they are absent") {
        // With every optional element: [1] and [2] hold five octets, [3] a SEQUENCE.
        SyntheticCertificate all{};
        all.issuerUniqueId = Bytes({0x81, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04});
        all.subjectUniqueId = Bytes({0x82, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04});
        const auto withAll = Must(ParseDer(all.Build()));
        CHECK_EQ(withAll.notBefore, kValidCertNotBefore);

        // Without the version (a v1 certificate) and without the extensions.
        SyntheticCertificate none{};
        none.version.clear();
        none.extensions.clear();
        const auto bare = Must(ParseDer(none.Build()));
        CHECK(std::memcmp(bare.publicKey.data(), kValidCertPublicKey, sizeof(kValidCertPublicKey)) == 0);
        CHECK_EQ(bare.notAfter, kValidCertNotAfter);
    }

    TEST_CASE("ParseCertificate accepts the long form of the length up to three octets") {
        // An extension of more than 65536 octets: the OCTET STRING, the extensions, the
        // tbsCertificate and the certificate all need three length octets.
        SyntheticCertificate certificate{};
        const std::vector<uint8_t> big(70000, 0x42);
        certificate.extensions = Tlv(0xA3, Seq({
            Seq({Bytes({0x06, 0x03, 0x55, 0x1D, 0x13}), Tlv(0x04, big)}),
        }));
        const std::vector<uint8_t> der = certificate.Build();
        REQUIRE(der.size() > 0x10000);
        const auto parsed = Must(ParseDer(der));
        CHECK_EQ(parsed.notBefore, kValidCertNotBefore);
        CHECK(parsed.signature.size() == 64);
        // The same certificate with one octet too many in the length is over-long.
        const std::vector<uint8_t> padded = Bytes({
            0x30, 0x84, 0x00, static_cast<int>(der[2]), static_cast<int>(der[3]), static_cast<int>(der[4]),
        });
        ExpectParseError(WithHeader(der, padded), "rule R2 der length is over-long");

        // The long form with three octets: an OCTET STRING of 65536 octets. Four octets name at
        // least 16 MiB, more than a test needs to build; the reader rejects longer forms.
        std::vector<uint8_t> huge(5 + 0x10000, 0x00);
        huge[0] = 0x04;
        huge[1] = 0x83;
        huge[2] = 0x01;
        cpl::cert::impl::DerElement element{};
        CHECK(cpl::cert::impl::DerReadHeader(huge.data(), huge.size(), element) == nullptr);
        CHECK(element.tag == 0x04);
        CHECK(element.contentSize == 0x10000);
        CHECK(cpl::cert::impl::DerReadHeader(huge.data(), huge.size() - 1, element) != nullptr);

        // The same value in the four octet form is over-long, and five octets are too many.
        const std::vector<uint8_t> overLong = {0x04, 0x84, 0x00, 0x01, 0x00, 0x00};
        CHECK(cpl::cert::impl::DerReadHeader(overLong.data(), overLong.size(), element) != nullptr);
        const std::vector<uint8_t> tooLong = {0x04, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00};
        CHECK(cpl::cert::impl::DerReadHeader(tooLong.data(), tooLong.size(), element) != nullptr);
    }

    TEST_CASE("ParseCertificate rejects malformed DER") {
        const std::vector<uint8_t> valid = ToVector(kValidCert, sizeof(kValidCert));
        REQUIRE(valid.size() > 300);

        // Every prefix is rejected; the empty input and a null pointer are rejected as well.
        ExpectParseError(std::vector<uint8_t>(), "rule R2 certificate der is empty");
        const auto nullPointer = ParseCertificate(nullptr, 0);
        REQUIRE_FALSE(nullPointer.has_value());
        CHECK_EQ(nullPointer.error().Code.i64, CertParseError);
        for (size_t size = 1; size < valid.size(); size++) {
            const std::vector<uint8_t> prefix(valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(size));
            ExpectParseError(prefix, "rule R2 der element is truncated");
        }

        // Trailing garbage: one octet, the end-of-contents octets, a second certificate.
        std::vector<uint8_t> garbage = valid;
        garbage.push_back(0x00);
        ExpectParseError(garbage, "rule R2 trailing garbage after the certificate");
        garbage.push_back(0x00);
        ExpectParseError(garbage, "rule R2 trailing garbage");
        garbage.insert(garbage.end(), valid.begin(), valid.end());
        ExpectParseError(garbage, "rule R2 trailing garbage");

        // The identifier and the length octets of the certificate are replaced.
        struct HeaderCase {
            const char *name;
            std::vector<uint8_t> octets;
            const char *rule;
        };
        const HeaderCase headers[] = {
            {"the indefinite form of the length", Bytes({0x30, 0x80}),
             "rule R2 der length uses the indefinite form"},
            {"the reserved length octet", Bytes({0x30, 0xFF}), "rule R2 der length octet is reserved"},
            {"five length octets", Bytes({0x30, 0x85, 0x00, 0x00, 0x00, 0x01, 0x54}),
             "rule R2 der length is longer than four octets"},
            {"a leading zero in the length", Bytes({0x30, 0x83, 0x00, 0x01, 0x54}),
             "rule R2 der length is over-long"},
            {"four length octets for a short length", Bytes({0x30, 0x84, 0x00, 0x00, 0x01, 0x54}),
             "rule R2 der length is over-long"},
            {"a length beyond the input", Bytes({0x30, 0x82, 0x7F, 0xFF}),
             "rule R2 der element is truncated"},
            {"a length shorter than the input", Bytes({0x30, 0x82, 0x01, 0x53}),
             "rule R2 trailing garbage after the certificate"},
            {"the high tag number form", Bytes({0x3F, 0x82, 0x01, 0x54}),
             "rule R2 der tag uses the high tag number form"},
            {"a primitive element with a high tag number", Bytes({0x1F, 0x82, 0x01, 0x54}),
             "rule R2 der tag uses the high tag number form"},
            {"a SET instead of a SEQUENCE", Bytes({0x31, 0x82, 0x01, 0x54}),
             "rule R2 certificate is not a sequence"},
            {"an INTEGER instead of a SEQUENCE", Bytes({0x02, 0x82, 0x01, 0x54}),
             "rule R2 certificate is not a sequence"},
        };
        for (const auto &header : headers) {
            const std::string caseName = header.name;
            INFO(caseName);
            std::vector<uint8_t> der = WithHeader(valid, header.octets);
            if (header.octets[1] == 0x80) {
                // The indefinite form ends with the end-of-contents octets.
                der.push_back(0x00);
                der.push_back(0x00);
            }
            ExpectParseError(der, header.rule);
        }
        // An input that ends inside the length octets.
        ExpectParseError(Bytes({0x30, 0x82, 0x01}), "rule R2 der element is truncated");
        // Well-formed DER, but no certificate.
        ExpectParseError(Bytes({0x30, 0x00}), "rule R2 certificate does not have exactly three elements");

        // Defects inside the elements.
        struct BodyCase {
            const char *name;
            std::vector<uint8_t> der;
            const char *rule;
        };
        const BodyCase bodies[] = {
            {"an indefinite length inside the certificate", Bytes({0x30, 0x04, 0x30, 0x80, 0x00, 0x00}),
             "rule R2 der length uses the indefinite form"},
            {"a long form for a short length inside", Bytes({0x30, 0x05, 0x30, 0x81, 0x02, 0x00, 0x00}),
             "rule R2 der length is over-long"},
            {"a leading zero inside", Bytes({0x30, 0x04, 0x30, 0x82, 0x00, 0x80}),
             "rule R2 der length is over-long"},
            {"five length octets inside", Bytes({0x30, 0x07, 0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00}),
             "rule R2 der length is longer than four octets"},
            // The truncated element lies inside the first element, so the certificate lacks its
            // other two elements: that is the first defect.
            {"a truncated element inside", Bytes({0x30, 0x06, 0x30, 0x04, 0x02, 0x03, 0x01, 0x02}),
             "rule R2 certificate does not have exactly three elements"},
            {"an element that reaches into its sibling", Bytes({0x30, 0x03, 0x02, 0x05, 0x01}),
             "rule R2 der element is truncated"},
            {"a dangling octet inside", Bytes({0x30, 0x04, 0x02, 0x01, 0x00, 0x00}),
             "rule R2 der element is truncated"},
            {"a high tag number inside", Bytes({0x30, 0x04, 0x3F, 0x81, 0x02, 0x00}),
             "rule R2 der tag uses the high tag number form"},
        };
        for (const auto &body : bodies) {
            const std::string caseName = body.name;
            INFO(caseName);
            ExpectParseError(body.der, body.rule);
        }
    }

    TEST_CASE("ParseCertificate rejects a certificate that does not match the template") {
        typedef void (*Mutation)(SyntheticCertificate &);
        struct Case {
            const char *name;
            Mutation mutate;
        };
        const Case cases[] = {
            {"version holds two integers",
             [](SyntheticCertificate &c) { c.version = Tlv(0xA0, Bytes({0x02, 0x01, 0x02, 0x02, 0x01, 0x02})); }},
            {"version holds an OID",
             [](SyntheticCertificate &c) { c.version = Tlv(0xA0, Bytes({0x06, 0x01, 0x2A})); }},
            {"version is empty",
             [](SyntheticCertificate &c) { c.version = Tlv(0xA0, Bytes({})); }},
            {"version is primitive",
             [](SyntheticCertificate &c) { c.version = Bytes({0x80, 0x03, 0x02, 0x01, 0x02}); }},
            {"no serial number",
             [](SyntheticCertificate &c) { c.serialNumber.clear(); }},
            {"serial number is an OCTET STRING",
             [](SyntheticCertificate &c) { c.serialNumber = Bytes({0x04, 0x01, 0x00}); }},
            {"serial number is an empty INTEGER",
             [](SyntheticCertificate &c) { c.serialNumber = Bytes({0x02, 0x00}); }},
            {"no signature algorithm in tbsCertificate",
             [](SyntheticCertificate &c) { c.tbsSignature.clear(); }},
            {"signature algorithm in tbsCertificate is an OCTET STRING",
             [](SyntheticCertificate &c) { c.tbsSignature = Bytes({0x04, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70}); }},
            {"signature algorithm in tbsCertificate is not well-formed",
             [](SyntheticCertificate &c) { c.tbsSignature = Seq({Bytes({0x06, 0x03, 0x2B, 0x65})}); }},
            {"no issuer",
             [](SyntheticCertificate &c) { c.issuer.clear(); }},
            {"issuer is an OCTET STRING",
             [](SyntheticCertificate &c) { c.issuer = Bytes({0x04, 0x00}); }},
            {"issuer is not well-formed",
             [](SyntheticCertificate &c) { c.issuer = Seq({Bytes({0x31, 0x80, 0x00, 0x00})}); }},
            {"no validity",
             [](SyntheticCertificate &c) { c.validity.clear(); }},
            {"validity has one time",
             [](SyntheticCertificate &c) { c.validity = Seq({UtcTime("260601000000Z")}); }},
            {"validity has three times",
             [](SyntheticCertificate &c) {
                 c.validity = Seq({UtcTime("260601000000Z"), UtcTime("280601000000Z"), UtcTime("280601000000Z")});
             }},
            {"validity is a Time",
             [](SyntheticCertificate &c) { c.validity = UtcTime("260601000000Z"); }},
            {"no subject",
             [](SyntheticCertificate &c) { c.subject.clear(); }},
            {"subject is an OCTET STRING",
             [](SyntheticCertificate &c) { c.subject = Bytes({0x04, 0x00}); }},
            {"no subject public key info",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo.clear(); }},
            {"subject public key info has one element",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm()}); }},
            {"subject public key info has three elements",
             [](SyntheticCertificate &c) {
                 c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), BitString(KeyBytes()), Bytes({0x05, 0x00})});
             }},
            {"subject public key algorithm is an OCTET STRING",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Bytes({0x04, 0x00}), BitString(KeyBytes())}); }},
            {"subject public key is an OCTET STRING",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), Tlv(0x04, KeyBytes())}); }},
            {"subject public key is an empty BIT STRING",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), Bytes({0x03, 0x00})}); }},
            {"subject public key BIT STRING has one unused bit",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), Tlv(0x03, Cat({Bytes({0x01}), KeyBytes()}))}); }},
            {"subject public key BIT STRING has seven unused bits",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), Tlv(0x03, Cat({Bytes({0x07}), KeyBytes()}))}); }},
            {"subject public key has no octets",
             [](SyntheticCertificate &c) { c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), Bytes({0x03, 0x01, 0x00})}); }},
            {"subject public key has 31 octets",
             [](SyntheticCertificate &c) {
                 const std::vector<uint8_t> key = KeyBytes();
                 c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), BitString(std::vector<uint8_t>(key.begin(), key.end() - 1))});
             }},
            {"subject public key has 33 octets",
             [](SyntheticCertificate &c) {
                 std::vector<uint8_t> longer = KeyBytes();
                 longer.push_back(0x00);
                 c.subjectPublicKeyInfo = Seq({Ed25519Algorithm(), BitString(longer)});
             }},
            {"issuerUniqueID is not well-formed",
             [](SyntheticCertificate &c) { c.issuerUniqueId = Bytes({0x81, 0x80}); }},
            {"extensions hold an indefinite length",
             [](SyntheticCertificate &c) { c.extensions = Tlv(0xA3, Bytes({0x30, 0x80})); }},
            {"no signature algorithm",
             [](SyntheticCertificate &c) { c.signatureAlgorithm.clear(); }},
            {"signature algorithm is not well-formed",
             [](SyntheticCertificate &c) { c.signatureAlgorithm = Seq({Bytes({0x06, 0x03, 0x2B, 0x65})}); }},
            {"no signature value",
             [](SyntheticCertificate &c) { c.signatureValue.clear(); }},
            {"signature value is an OCTET STRING",
             [](SyntheticCertificate &c) { c.signatureValue = Tlv(0x04, std::vector<uint8_t>(64, 0x5A)); }},
            {"signature value is an empty BIT STRING",
             [](SyntheticCertificate &c) { c.signatureValue = Bytes({0x03, 0x00}); }},
            {"signature value BIT STRING has one unused bit",
             [](SyntheticCertificate &c) { c.signatureValue = Tlv(0x03, Cat({Bytes({0x01}), std::vector<uint8_t>(64, 0x5A)})); }},
            {"signature value BIT STRING has seven unused bits",
             [](SyntheticCertificate &c) { c.signatureValue = Tlv(0x03, Cat({Bytes({0x07}), std::vector<uint8_t>(64, 0x5A)})); }},
        };
        for (const auto &item : cases) {
            INFO(item.name);
            SyntheticCertificate certificate{};
            item.mutate(certificate);
            ExpectParseError(certificate.Build(), "rule R2 ");
        }

        // The shape of the certificate itself.
        SyntheticCertificate certificate{};
        ExpectParseError(Seq({Bytes({0x02, 0x01, 0x00}), certificate.signatureAlgorithm, certificate.signatureValue}),
                         "rule R2 tbs certificate is not a sequence");
        ExpectParseError(Seq({certificate.Tbs(), certificate.signatureAlgorithm}),
                         "rule R2 certificate does not have exactly three elements");
        ExpectParseError(Seq({certificate.Tbs(), certificate.signatureAlgorithm, certificate.signatureValue,
                              certificate.signatureValue}),
                         "rule R2 certificate does not have exactly three elements");
        ExpectParseError(Tlv(0x30, Bytes({0x30, 0x80})),
                         "rule R2 der length uses the indefinite form");

        // The optional elements come in one order and appear once.
        certificate.extensions.clear();
        const std::vector<uint8_t> uniqueId = Bytes({0x81, 0x02, 0x00, 0x01});
        const std::vector<uint8_t> extensionElement = SyntheticCertificate().extensions;
        // The mandatory elements, up to the subject public key info.
        const std::vector<uint8_t> mandatory = certificate.Fields();
        const std::vector<uint8_t> unknown = Bytes({0xA4, 0x03, 0x02, 0x01, 0x02});
        // [3] with a well-formed header and an element of the indefinite form inside. The
        // identifiers [1] and [2] are primitive: any content of theirs is well-formed.
        const std::vector<uint8_t> malformed = Bytes({0xA3, 0x02, 0x30, 0x80});
        const char *const unexpected = "rule R2 tbs certificate has an unexpected element";
        const auto certificateWith = [&](const std::vector<uint8_t> &fields) {
            return Seq({Tlv(0x30, Cat({fields})), certificate.signatureAlgorithm, certificate.signatureValue});
        };
        ExpectParseError(certificateWith(Cat({mandatory, extensionElement, uniqueId})),
                         unexpected); // [3] before [1]
        ExpectParseError(certificateWith(Cat({mandatory, uniqueId, uniqueId, extensionElement})),
                         unexpected); // [1] twice
        ExpectParseError(certificateWith(Cat({mandatory, extensionElement, extensionElement})),
                         unexpected); // [3] twice
        ExpectParseError(certificateWith(Cat({mandatory, unknown})),
                         unexpected); // [4] does not exist
        ExpectParseError(certificateWith(Cat({mandatory, malformed})),
                         "rule R2 tbs certificate optional element is not well-formed der");
        // In their order they are accepted.
        const auto ordered = Must(ParseDer(certificateWith(Cat({mandatory, uniqueId, Bytes({0x82, 0x02, 0x00, 0x01}),
                                                               extensionElement}))));
        CHECK(ordered.notBefore == kValidCertNotBefore);
    }

    TEST_CASE("ParseCertificate rejects every algorithm other than Ed25519 without parameters") {
        struct OtherAlgorithm {
            const char *name;
            std::vector<uint8_t> identifier;
        };
        const OtherAlgorithm others[] = {
            {"ecdsa-with-SHA256", EcdsaWithSha256()},
            {"the algorithm of an EC P-256 key", EcP256Algorithm()},
            {"Ed25519 with a NULL parameter", Ed25519WithNull()},
            {"Ed25519 with an empty SEQUENCE as parameter",
             Seq({Bytes({0x06, 0x03, 0x2B, 0x65, 0x70}), Bytes({0x30, 0x00})})},
            {"Ed448", Seq({Bytes({0x06, 0x03, 0x2B, 0x65, 0x71})})},
        };
        for (const auto &other : others) {
            const std::string caseName = other.name;
            INFO(caseName);
            SyntheticCertificate inside{};
            inside.tbsSignature = other.identifier;
            ExpectParseError(inside.Build(), "rule R3 tbs certificate signature algorithm");
            SyntheticCertificate outside{};
            outside.signatureAlgorithm = other.identifier;
            ExpectParseError(outside.Build(), "rule R3 certificate signature algorithm");
            SyntheticCertificate key{};
            key.subjectPublicKeyInfo = Seq({other.identifier, BitString(KeyBytes())});
            ExpectParseError(key.Build(), "rule R3 subject public key algorithm");
        }

        // A bare OID is not an AlgorithmIdentifier. That is a defect of the structure, so it
        // violates R2 in every position.
        SyntheticCertificate bareInside{};
        bareInside.tbsSignature = Bytes({0x06, 0x03, 0x2B, 0x65, 0x70});
        ExpectParseError(bareInside.Build(),
                         "rule R2 tbs certificate signature algorithm is missing or has the wrong tag");
        SyntheticCertificate bareOutside{};
        bareOutside.signatureAlgorithm = Bytes({0x06, 0x03, 0x2B, 0x65, 0x70});
        ExpectParseError(bareOutside.Build(), "rule R2 signature algorithm is not a well-formed sequence");
        SyntheticCertificate bareKey{};
        bareKey.subjectPublicKeyInfo = Seq({Bytes({0x06, 0x03, 0x2B, 0x65, 0x70}), BitString(KeyBytes())});
        ExpectParseError(bareKey.Build(), "rule R2 subject public key algorithm is not a well-formed sequence");
    }

    TEST_CASE("ParseCertificate rejects the certificates with a defect that the generator built") {
        ExpectParseError(ToVector(kEcdsaCert, sizeof(kEcdsaCert)), "rule R3 subject public key algorithm");
        ExpectParseError(ToVector(kOuterAlgMismatchCert, sizeof(kOuterAlgMismatchCert)),
                         "rule R3 certificate signature algorithm");
        ExpectParseError(ToVector(kTbsAlgMismatchCert, sizeof(kTbsAlgMismatchCert)),
                         "rule R3 tbs certificate signature algorithm");
        ExpectParseError(ToVector(kNullParamsAlgCert, sizeof(kNullParamsAlgCert)),
                         "rule R3 tbs certificate signature algorithm");
        ExpectParseError(ToVector(kUnusedBitsSigCert, sizeof(kUnusedBitsSigCert)),
                         "rule R2 signature value bit string");
        ExpectParseError(ToVector(kUnusedBitsKeyCert, sizeof(kUnusedBitsKeyCert)),
                         "rule R2 subject public key bit string");
        ExpectParseError(ToVector(kLongKeyCert, sizeof(kLongKeyCert)),
                         "rule R2 subject public key is not 32 bytes");
        // The forged certificate is well-formed: who signed it is not a question of parsing.
        const auto forged = Must(ParseDer(ToVector(kForgedCert, sizeof(kForgedCert))));
        CHECK(forged.notBefore == kValidCertNotBefore);
    }

    TEST_CASE("VerifyIssuedBy accepts a certificate of the root inside its window") {
        const auto cert = Must(ParseDer(ToVector(kValidCert, sizeof(kValidCert))));
        CHECK_EQ(Must(VerifyIssuedBy(cert, kRootPublicKey, kFixedNow)), 0);
        CHECK_EQ(Must(VerifyIssuedBy(cert, kRootPublicKey, kValidCertNotBefore)), 0);
        CHECK_EQ(Must(VerifyIssuedBy(cert, kRootPublicKey, kValidCertNotAfter)), 0);
    }

    TEST_CASE("VerifyIssuedBy applies R5 with a grace of one day before notBefore") {
        const auto cert = Must(ParseDer(ToVector(kValidCert, sizeof(kValidCert))));
        CHECK_EQ(Must(VerifyIssuedBy(cert, kRootPublicKey, kValidCertNotBefore - 86400)), 0);
        // One second before the grace and one second after notAfter.
        const auto early = ExpectRule(VerifyIssuedBy(cert, kRootPublicKey, kValidCertNotBefore - 86401), 5);
        CHECK(early.Reason.find("not yet valid") != std::string::npos);
        const auto late = ExpectRule(VerifyIssuedBy(cert, kRootPublicKey, kValidCertNotAfter + 1), 5);
        CHECK(late.Reason.find("expired") != std::string::npos);
        // The extremes of the time argument do not overflow.
        ExpectRule(VerifyIssuedBy(cert, kRootPublicKey, INT64_MIN), 5);
        ExpectRule(VerifyIssuedBy(cert, kRootPublicKey, INT64_MAX), 5);

        const auto expired = Must(ParseDer(ToVector(kExpiredCert, sizeof(kExpiredCert))));
        const auto expiredError = ExpectRule(VerifyIssuedBy(expired, kRootPublicKey, kFixedNow), 5);
        CHECK(expiredError.Reason.find("expired") != std::string::npos);
        CHECK_EQ(Must(VerifyIssuedBy(expired, kRootPublicKey, kExpiredCertNotAfter)), 0);
        ExpectRule(VerifyIssuedBy(expired, kRootPublicKey, kExpiredCertNotAfter + 1), 5);
        CHECK_EQ(Must(VerifyIssuedBy(expired, kRootPublicKey, kExpiredCertNotBefore - 86400)), 0);
        ExpectRule(VerifyIssuedBy(expired, kRootPublicKey, kExpiredCertNotBefore - 86401), 5);

        const auto notYetValid = Must(ParseDer(ToVector(kNotYetValidCert, sizeof(kNotYetValidCert))));
        const auto future = ExpectRule(VerifyIssuedBy(notYetValid, kRootPublicKey, kFixedNow), 5);
        CHECK(future.Reason.find("not yet valid") != std::string::npos);
        CHECK_EQ(Must(VerifyIssuedBy(notYetValid, kRootPublicKey, kNotYetValidCertNotBefore - 86400)), 0);
    }

    TEST_CASE("VerifyIssuedBy rejects a certificate that the root did not sign with rule 4") {
        const auto cert = Must(ParseDer(ToVector(kValidCert, sizeof(kValidCert))));
        const std::vector<uint8_t> zero(32, 0x00);
        ExpectRule(VerifyIssuedBy(cert, kOtherRootPublicKey, kFixedNow), 4);
        ExpectRule(VerifyIssuedBy(cert, zero.data(), kFixedNow), 4);

        // The forged certificate is well-formed and inside its window: only its signer is wrong.
        const auto forged = Must(ParseDer(ToVector(kForgedCert, sizeof(kForgedCert))));
        CHECK(forged.notBefore == kValidCertNotBefore);
        ExpectRule(VerifyIssuedBy(forged, kRootPublicKey, kFixedNow), 4);
        CHECK_EQ(Must(VerifyIssuedBy(forged, kOtherRootPublicKey, kFixedNow)), 0);
        // R4 comes before R5.
        ExpectRule(VerifyIssuedBy(forged, kRootPublicKey, INT64_MIN), 4);

        // A changed octet in tbsCertificate breaks the signature.
        Certificate changed = cert;
        changed.tbs[20] ^= 0x01;
        ExpectRule(VerifyIssuedBy(changed, kRootPublicKey, kFixedNow), 4);
        // A certificate whose signature is not 64 octets is not the object of an Ed25519 signature.
        Certificate broken = cert;
        broken.signature.pop_back();
        ExpectRule(VerifyIssuedBy(broken, kRootPublicKey, kFixedNow), 4);
        broken = cert;
        broken.signature.push_back(0x00);
        ExpectRule(VerifyIssuedBy(broken, kRootPublicKey, kFixedNow), 4);
        broken = cert;
        broken.signature.clear();
        broken.tbs.clear();
        ExpectRule(VerifyIssuedBy(broken, kRootPublicKey, kFixedNow), 4);
    }

    TEST_CASE("a null key is rejected before any rule") {
        const auto cert = Must(ParseDer(ToVector(kValidCert, sizeof(kValidCert))));
        const auto issued = VerifyIssuedBy(cert, nullptr, kFixedNow);
        REQUIRE_FALSE(issued.has_value());
        CHECK_EQ(issued.error().Code.i64, static_cast<int64_t>(cpl::Error::NullPointer));
        CHECK(issued.error().Reason.find("cert.hpp:") != std::string::npos);
        const auto verified = VerifyConfigJwt(kValidJwt, nullptr, kFixedNow);
        REQUIRE_FALSE(verified.has_value());
        CHECK_EQ(verified.error().Code.i64, static_cast<int64_t>(cpl::Error::NullPointer));
        CHECK(verified.error().Reason.find("cert.hpp:") != std::string::npos);
    }

    TEST_CASE("VerifyConfigJwt accepts the valid token and returns its payload") {
        ExpectAccepted(kValidJwt);
        ExpectAcceptedAt(kValidJwt, kFixedNow - 86400);
        ExpectAcceptedAt(kValidJwt, kFixedNow + 86400);
        // The payload is the decoded segment, byte for byte the text that was signed.
        const auto verified = Must(VerifyConfigJwt(kValidJwt, kRootPublicKey, kFixedNow));
        CHECK(verified.payloadJson == LibraryDecode(SplitToken(kValidJwt)[1]));

        // Members that the rules do not mention are ignored.
        const auto extra = Must(VerifyConfigJwt(kExtraMembersJwt, kRootPublicKey, kFixedNow));
        CHECK(extra.group == "default");
        CHECK(extra.serial == kValidSerial);
        CHECK(extra.payloadJson == LibraryDecode(SplitToken(kExtraMembersJwt)[1]));
        CHECK(ParseJson(extra.payloadJson)["to"] == "00");
    }

    TEST_CASE("VerifyConfigJwt maps every rejection vector to its rule") {
        struct Rejection {
            const char *name;
            const char *token;
            int rule;
            const char *phrase; // part of the reason
        };
        const Rejection rejections[] = {
            {"an expired token", kExpiredJwt, 8, "rule R8 jwt is expired"},
            {"a token from the future", kNotYetValidJwt, 8, "rule R8 jwt is not yet valid"},
            {"a tampered token", kTamperedJwt, 6, "rule R6 jwt signature verify failed"},
            {"two certificates in x5c", kTwoCertsJwt, 1, "rule R1 jwt header x5c"},
            {"alg HS256", kHs256Jwt, 1, "rule R1 jwt header alg is not EdDSA"},
            {"no x5c", kNoX5cJwt, 1, "rule R1 jwt header x5c"},
            {"a payload without config", kNoConfigJwt, 1, "rule R1 jwt payload config"},
            {"a fourth segment", kFourSegmentsJwt, 1, "rule R1 jwt does not have exactly three segments"},
            {"a signature by a key that is not the key of the certificate", kWrongKeyJwt, 6,
             "rule R6 jwt signature verify failed"},
            {"an expired certificate", kExpiredCertJwt, 5, "rule R5 jwt certificate is expired"},
            {"a certificate that is not valid yet", kNotYetValidCertJwt, 5, "rule R5 jwt certificate is not yet valid"},
            {"a forged certificate", kForgedCertJwt, 4, "rule R4 certificate signature verify failed"},
            {"a certificate with an ECDSA key", kEcdsaCertJwt, 3, "rule R3 subject public key algorithm"},
            {"a certificate with another algorithm inside tbsCertificate", kTbsAlgMismatchCertJwt, 3,
             "rule R3 tbs certificate signature algorithm"},
            {"a certificate with another outer algorithm", kOuterAlgMismatchCertJwt, 3,
             "rule R3 certificate signature algorithm"},
            {"a truncated certificate", kTruncatedCertJwt, 2, "rule R2 der element is truncated"},
            {"a certificate followed by garbage", kGarbageCertJwt, 2, "rule R2 trailing garbage"},
        };
        for (const auto &rejection : rejections) {
            INFO(rejection.name);
            const cpl::Error error = ExpectJwtRule(rejection.token, rejection.rule);
            CHECK_MESSAGE(error.Reason.find(rejection.phrase) != std::string::npos,
                          error.Reason << " does not contain " << rejection.phrase);
        }
    }

    TEST_CASE("VerifyConfigJwt checks the rules in their order") {
        // A token that breaks several rules reports the first one, whatever the root key is.
        const std::vector<std::string> expired = SplitToken(kExpiredCertJwt);
        const std::string foreignSignature = SplitToken(kWrongKeyJwt)[2];
        // R5 before R6: the expired certificate is reported, the foreign signature is not looked at.
        ExpectJwtRule(JoinToken({expired[0], expired[1], foreignSignature}), 5);
        // R4 before R5, R3 before R4, R2 before R3, R1 before everything.
        ExpectRule(VerifyConfigJwt(kForgedCertJwt, kRootPublicKey, INT64_MIN), 4);
        ExpectRule(VerifyConfigJwt(kEcdsaCertJwt, kOtherRootPublicKey, kFixedNow), 3);
        ExpectRule(VerifyConfigJwt(kTruncatedCertJwt, kOtherRootPublicKey, kFixedNow), 2);
        ExpectRule(VerifyConfigJwt(kNoX5cJwt, kOtherRootPublicKey, kFixedNow), 1);
        ExpectRule(VerifyConfigJwt(kHs256Jwt, kOtherRootPublicKey, kFixedNow), 1);
        // R8 is not reached with a time argument outside the window of the certificate: R5 fires first.
        ExpectJwtRuleAt(kValidJwt, 5, kValidCertNotBefore - 86401);
        ExpectJwtRuleAt(kValidJwt, 5, INT64_MIN);
        ExpectJwtRuleAt(kValidJwt, 5, INT64_MAX);
    }

    TEST_CASE("VerifyConfigJwt applies R8 with a grace of one day before iat") {
        ExpectAcceptedAt(kValidJwt, kValidIat - 86400);
        ExpectAcceptedAt(kValidJwt, kValidExp);
        // One second before the grace and one second after exp.
        const auto early = ExpectJwtRuleAt(kValidJwt, 8, kValidIat - 86401);
        CHECK(early.Reason.find("not yet valid") != std::string::npos);
        const auto late = ExpectJwtRuleAt(kValidJwt, 8, kValidExp + 1);
        CHECK(late.Reason.find("expired") != std::string::npos);
        // Thirty days before the token was issued.
        ExpectJwtRuleAt(kValidJwt, 8, kFixedNow - 30 * 86400);
    }

    TEST_CASE("VerifyConfigJwt with SkipTime leaves out R5 and R8 and nothing else") {
        ExpectAccepted(kExpiredJwt, SkipTime);
        ExpectAccepted(kNotYetValidJwt, SkipTime);
        ExpectAccepted(kExpiredCertJwt, SkipTime);
        ExpectAccepted(kNotYetValidCertJwt, SkipTime);
        // The time argument does not matter any more, not even at its extremes.
        for (const int64_t now : {INT64_MIN, int64_t(0), kFixedNow, INT64_MAX}) {
            const auto expiredToken = Must(VerifyConfigJwt(kExpiredJwt, kRootPublicKey, now, SkipTime));
            CHECK(expiredToken.serial == kValidSerial);
            const auto expiredCertificate = Must(VerifyConfigJwt(kExpiredCertJwt, kRootPublicKey, now, SkipTime));
            CHECK(expiredCertificate.payloadJson == kValidPayloadJson);
        }
        // Everything that is not a time rule is rejected as before.
        ExpectJwtRule(kTamperedJwt, 6, SkipTime);
        ExpectJwtRule(kWrongKeyJwt, 6, SkipTime);
        ExpectJwtRule(kForgedCertJwt, 4, SkipTime);
        ExpectJwtRule(kEcdsaCertJwt, 3, SkipTime);
        ExpectJwtRule(kTbsAlgMismatchCertJwt, 3, SkipTime);
        ExpectJwtRule(kOuterAlgMismatchCertJwt, 3, SkipTime);
        ExpectJwtRule(kTruncatedCertJwt, 2, SkipTime);
        ExpectJwtRule(kGarbageCertJwt, 2, SkipTime);
        ExpectJwtRule(kTwoCertsJwt, 1, SkipTime);
        ExpectJwtRule(kHs256Jwt, 1, SkipTime);
        ExpectJwtRule(kNoX5cJwt, 1, SkipTime);
        ExpectJwtRule(kNoConfigJwt, 1, SkipTime);
        ExpectJwtRule(kFourSegmentsJwt, 1, SkipTime);
    }

    TEST_CASE("VerifyConfigJwt treats every check value other than SkipTime as EnforceTime") {
        const int32_t values[] = {EnforceTime, 0, 2, -1, 99, INT32_MAX, INT32_MIN};
        for (const int32_t value : values) {
            INFO(value);
            ExpectAccepted(kValidJwt, value);
            ExpectJwtRule(kExpiredJwt, 8, value);
            ExpectJwtRule(kExpiredCertJwt, 5, value);
        }
        // SkipTime itself is the value 1.
        ExpectAccepted(kExpiredJwt, 1);
        ExpectAccepted(kExpiredCertJwt, 1);
    }

    TEST_CASE("VerifyConfigJwt rejects a wrong root key with rule 4") {
        ExpectRule(VerifyConfigJwt(kValidJwt, kOtherRootPublicKey, kFixedNow), 4);
        const std::vector<uint8_t> zero(32, 0x00);
        ExpectRule(VerifyConfigJwt(kValidJwt, zero.data(), kFixedNow), 4);
        ExpectRule(VerifyConfigJwt(kValidJwt, kOtherRootPublicKey, kFixedNow, SkipTime), 4);
        // The other root accepts the certificate that it signed, and still checks the token.
        const auto forged = Must(VerifyConfigJwt(kForgedCertJwt, kOtherRootPublicKey, kFixedNow));
        CHECK(forged.serial == kValidSerial);
        const std::vector<std::string> segments = SplitToken(kValidJwt);
        ExpectRule(VerifyConfigJwt(JoinToken({SplitToken(kForgedCertJwt)[0], segments[1], segments[2]}),
                                   kOtherRootPublicKey, kFixedNow),
                   6);
    }

    TEST_CASE("VerifyConfigJwt reports R1 for a token with the wrong shape") {
        const nlohmann::json header = ValidHeader();
        const nlohmann::json payload = ValidPayload();
        const std::string payloadText = Dump(payload);
        const nlohmann::json nullValue(nlohmann::json(nullptr));
        const std::vector<std::pair<const char *, std::string> > cases = {
            {"an empty token", ""},
            {"one segment", "abc"},
            {"two segments", "abc.def"},
            {"four segments", "a.b.c.d"},
            {"nothing but separators", ".."},
            {"an empty header", Token("", payloadText)},
            {"an empty payload", Token(Dump(header), "")},
            {"a header that is not JSON", Token("{", payloadText)},
            {"a header that is an array", Token("[1]", payloadText)},
            {"a header that is a string", Token("\"x\"", payloadText)},
            {"a header with invalid UTF-8", Token("{\"alg\":\"\xff\"}", payloadText)},
            {"a payload that is not JSON", Token(Dump(header), "{")},
            {"a payload that is an array", Token(Dump(header), "[]")},
            {"a payload that is a string", Token(Dump(header), "\"x\"")},
            {"a payload with invalid UTF-8", Token(Dump(header), "{\"group\":\"\xff\"}")},
            {"no alg", Token(Without(header, "alg"), payload)},
            {"alg in lower case", Token(With(header, "alg", "edsa"), payload)},
            {"alg RS256", Token(With(header, "alg", "RS256"), payload)},
            {"alg is a number", Token(With(header, "alg", 7), payload)},
            {"alg is null", Token(With(header, "alg", nullValue), payload)},
            {"no x5c", Token(Without(header, "x5c"), payload)},
            {"x5c is a string", Token(With(header, "x5c", "abc"), payload)},
            {"x5c is an empty array", Token(With(header, "x5c", std::vector<std::string>()), payload)},
            {"x5c holds a number", Token(With(header, "x5c", std::vector<int>{42}), payload)},
            {"x5c is an object", Token(With(header, "x5c", nlohmann::json::object()), payload)},
            {"no group", Token(header, Without(payload, "group"))},
            {"group is a number", Token(header, With(payload, "group", 1))},
            {"group is null", Token(header, With(payload, "group", nullValue))},
            {"no serial", Token(header, Without(payload, "serial"))},
            {"serial is a string", Token(header, With(payload, "serial", "42"))},
            {"serial is a float", Token(header, With(payload, "serial", 42.5))},
            {"serial is a boolean", Token(header, With(payload, "serial", true))},
            {"serial is null", Token(header, With(payload, "serial", nullValue))},
            {"serial is an array", Token(header, With(payload, "serial", std::vector<int>{42}))},
            {"serial is written as an exponent",
             Token(Dump(header), ReplaceOnce(payloadText, "\"serial\":42", "\"serial\":4e2"))},
            {"serial is 2^64 - 1",
             Token(Dump(header), ReplaceOnce(payloadText, "\"serial\":42", "\"serial\":18446744073709551615"))},
            {"serial is 2^63",
             Token(Dump(header), ReplaceOnce(payloadText, "\"serial\":42", "\"serial\":9223372036854775808"))},
            {"no iat", Token(header, Without(payload, "iat"))},
            {"iat is a string", Token(header, With(payload, "iat", "1799996400"))},
            {"iat is a float", Token(header, With(payload, "iat", 1.5))},
            {"no exp", Token(header, Without(payload, "exp"))},
            {"exp is a float", Token(header, With(payload, "exp", 1.5))},
            {"no config", Token(header, Without(payload, "config"))},
            {"config is an array", Token(header, With(payload, "config", std::vector<int>{1}))},
            {"config is a string", Token(header, With(payload, "config", "x"))},
            {"config is null", Token(header, With(payload, "config", nullValue))},
        };
        for (const auto &item : cases) {
            INFO(item.first);
            ExpectJwtRule(item.second, 1);
        }
    }

    TEST_CASE("VerifyConfigJwt reports R2 for text that is not canonical base64url") {
        const std::vector<std::string> segments = SplitToken(kValidJwt);
        REQUIRE(segments.size() == 3);
        const nlohmann::json header = ValidHeader();
        const nlohmann::json payload = ValidPayload();
        const std::vector<std::pair<const char *, std::string> > cases = {
            {"a plus in the header segment", JoinToken({ReplaceAt(segments[0], 10, '+'), segments[1], segments[2]})},
            {"a slash in the header segment", JoinToken({ReplaceAt(segments[0], 10, '/'), segments[1], segments[2]})},
            {"padding in the header segment", JoinToken({segments[0] + "=", segments[1], segments[2]})},
            {"a space in the header segment", ReplaceAt(kValidJwt, 8, ' ')},
            {"a NUL in the header segment", JoinToken({ReplaceAt(segments[0], 10, '\0'), segments[1], segments[2]})},
            {"the header segment has length 1 modulo 4",
             JoinToken({PadToRemainderOne(segments[0]), segments[1], segments[2]})},
            {"the header segment is not canonical", JoinToken({NonCanonical(segments[0]), segments[1], segments[2]})},
            {"a plus in the payload segment", JoinToken({segments[0], ReplaceAt(segments[1], 10, '+'), segments[2]})},
            {"padding in the payload segment", JoinToken({segments[0], segments[1] + "=", segments[2]})},
            {"a NUL in the payload segment", JoinToken({segments[0], ReplaceAt(segments[1], 10, '\0'), segments[2]})},
            {"the payload segment is not canonical", JoinToken({segments[0], NonCanonical(segments[1]), segments[2]})},
            {"a plus in the signature segment", JoinToken({segments[0], segments[1], ReplaceAt(segments[2], 10, '+')})},
            {"a slash in the signature segment", JoinToken({segments[0], segments[1], ReplaceAt(segments[2], 10, '/')})},
            {"padding in the signature segment", JoinToken({segments[0], segments[1], segments[2] + "="})},
            {"the signature segment is one character short",
             JoinToken({segments[0], segments[1], segments[2].substr(0, segments[2].size() - 1)})},
            {"the signature segment has length 1 modulo 4",
             JoinToken({segments[0], segments[1], PadToRemainderOne(segments[2])})},
            {"the signature segment is not canonical", JoinToken({segments[0], segments[1], NonCanonical(segments[2])})},
            {"x5c holds text with a plus",
             Token(With(header, "x5c", std::vector<std::string>{"ab+cd"}), payload)},
            {"x5c holds padded text", Token(With(header, "x5c", std::vector<std::string>{"abcd="}), payload)},
            {"x5c holds an empty string", Token(With(header, "x5c", std::vector<std::string>{""}), payload)},
            {"x5c holds text with a NUL",
             Token(With(header, "x5c", std::vector<std::string>{std::string("ab\0cd", 5)}), payload)},
        };
        for (const auto &item : cases) {
            INFO(item.first);
            ExpectJwtRule(item.second, 2);
        }
    }

    TEST_CASE("VerifyConfigJwt reports R2 for a certificate that is not valid DER") {
        const nlohmann::json header = ValidHeader();
        const nlohmann::json payload = ValidPayload();
        const auto withCertificate = [&](const std::vector<uint8_t> &der) {
            return Token(With(header, "x5c", std::vector<std::string>{LibraryEncode(
                                              std::string(der.begin(), der.end()))}),
                         payload);
        };
        const std::vector<uint8_t> valid = ToVector(kValidCert, sizeof(kValidCert));
        ExpectJwtRule(withCertificate(std::vector<uint8_t>(valid.begin(), valid.begin() + 200)), 2);
        ExpectJwtRule(withCertificate(ToVector(kUnusedBitsSigCert, sizeof(kUnusedBitsSigCert))), 2);
        ExpectJwtRule(withCertificate(ToVector(kUnusedBitsKeyCert, sizeof(kUnusedBitsKeyCert))), 2);
        ExpectJwtRule(withCertificate(ToVector(kLongKeyCert, sizeof(kLongKeyCert))), 2);
        ExpectJwtRule(withCertificate(ToVector(kNullParamsAlgCert, sizeof(kNullParamsAlgCert))), 3);
    }

    TEST_CASE("VerifyConfigJwt reports R6 for a signature that is not 64 valid octets") {
        const std::vector<std::string> segments = SplitToken(kValidJwt);
        const std::vector<std::pair<const char *, std::string> > cases = {
            {"an empty signature", JoinToken({segments[0], segments[1], ""})},
            {"a signature of 63 octets", JoinToken({segments[0], segments[1], LibraryEncode(std::string(63, 'x'))})},
            {"a signature of 65 octets", JoinToken({segments[0], segments[1], LibraryEncode(std::string(65, 'x'))})},
            {"a signature of 32 octets", JoinToken({segments[0], segments[1], LibraryEncode(std::string(32, 'x'))})},
            {"a signature of 64 zero octets",
             JoinToken({segments[0], segments[1], LibraryEncode(std::string(64, '\0'))})},
            {"the signature of a token that another key signed",
             JoinToken({segments[0], segments[1], SplitToken(kWrongKeyJwt)[2]})},
            {"the signature of another token",
             JoinToken({segments[0], segments[1], SplitToken(kExpiredJwt)[2]})},
            {"a signature with one character changed", JoinToken({segments[0], segments[1], FlipAt(segments[2], 20)})},
            {"a signature with another character changed", JoinToken({segments[0], segments[1], FlipAt(segments[2], 60)})},
        };
        for (const auto &item : cases) {
            INFO(item.first);
            ExpectJwtRule(item.second, 6);
        }
    }

    TEST_CASE("VerifyConfigJwt rejects every third character of the valid token being changed") {
        const std::string token = kValidJwt;
        size_t tested = 0;
        for (size_t position = 0; position < token.size(); position += 3) {
            const auto result = VerifyConfigJwt(FlipAt(token, position), kRootPublicKey, kFixedNow);
            CHECK_MESSAGE(!result.has_value(), "position " << position);
            ++tested;
        }
        CHECK(tested > 300);
    }

    TEST_CASE("the base64url decoder is canonical and agrees with the library decoder") {
        // The library decoder is the reference for canonical text, and the encoder of the
        // library writes canonical text.
        for (const auto &segment : SplitToken(kValidJwt)) {
            std::string decoded;
            REQUIRE(cpl::cert::impl::Base64UrlDecode(segment, decoded));
            CHECK(decoded == LibraryDecode(segment));
            CHECK(LibraryEncode(decoded) == segment);
        }
        for (size_t length = 1; length <= 70; length++) {
            std::string text(length, '\0');
            for (size_t i = 0; i < length; i++) {
                text[i] = static_cast<char>((i * 37 + 5) & 0xFF);
            }
            std::string decoded;
            REQUIRE(cpl::cert::impl::Base64UrlDecode(LibraryEncode(text), decoded));
            CHECK(decoded == text);
        }
        // Text that no canonical encoder writes.
        const std::vector<std::string> rejected = {
            "A", "AAAAA", "AB", "AAB", "AA==", "AA=", "AAA=", "AAAA=", "A A", "A+A", "A/A", "A.A",
            "A-A-A", std::string("A\0A", 3),
        };
        for (const auto &text : rejected) {
            std::string decoded;
            INFO(text);
            CHECK_FALSE(cpl::cert::impl::Base64UrlDecode(text, decoded));
        }
        // "AB" and "AA" decode to the same octet. The library decoder accepts both; the
        // canonical decoder accepts only "AA", so one byte string has one text.
        CHECK(LibraryDecode("AB") == LibraryDecode("AA"));
        std::string decoded;
        CHECK(cpl::cert::impl::Base64UrlDecode("AA", decoded));
        CHECK(decoded == std::string(1, '\0'));
        CHECK_FALSE(cpl::cert::impl::Base64UrlDecode("AB", decoded));
        // Empty text is the canonical text of no octets.
        CHECK(cpl::cert::impl::Base64UrlDecode("", decoded));
        CHECK(decoded.empty());
        // The output is cleared when the text is rejected.
        decoded = "left over";
        CHECK_FALSE(cpl::cert::impl::Base64UrlDecode("QUJD+", decoded));
        CHECK(decoded.empty());
    }

    TEST_CASE("the day grace does not overflow at the smallest int64_t") {
        CHECK(cpl::cert::impl::IsWithinDayBefore(INT64_MIN, INT64_MIN));
        CHECK(cpl::cert::impl::IsWithinDayBefore(INT64_MIN, INT64_MIN + 86400));
        CHECK(cpl::cert::impl::IsWithinDayBefore(INT64_MIN + 1, INT64_MIN + 86401));
        CHECK_FALSE(cpl::cert::impl::IsWithinDayBefore(INT64_MIN, INT64_MIN + 86401));
        CHECK(cpl::cert::impl::IsWithinDayBefore(kFixedNow, kFixedNow + 86400));
        CHECK_FALSE(cpl::cert::impl::IsWithinDayBefore(kFixedNow, kFixedNow + 86401));
        CHECK(cpl::cert::impl::IsWithinDayBefore(INT64_MAX, INT64_MAX));
    }
}

