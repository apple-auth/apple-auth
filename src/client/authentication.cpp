#include "client/client_internal.hpp"
#include "crypto/backend.hpp"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <mbedtls/gcm.h>
#include <memory>

namespace apple_auth::netdetail {

namespace {
Bytes binary(const Json& v, const std::string& key) {
    require(v.contains(key) && v.at(key).is_binary(), "GrandSlam missing binary field: " + key);
    return v.at(key).get_binary();
}

std::string text(const Json& v, const std::string& key) {
    require(v.contains(key) && v.at(key).is_string() &&
                !v.at(key).get_ref<const std::string&>().empty(),
            "GrandSlam missing string field: " + key);
    return v.at(key).get<std::string>();
}

void status(const Json& response) {
    if (!response.contains("Status")) {
        return;
    }
    const auto& s = response.at("Status");
    require(s.is_object(), "Malformed GrandSlam status");
    auto code = s.value("ec", std::int64_t(0));
    if (code != 0) {
        throw Error("Apple authentication rejected (code " + std::to_string(code) + ")");
    }
}

std::string now(std::int64_t seconds) {
    auto t = static_cast<std::time_t>(seconds);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char out[32];
    std::strftime(out, sizeof out, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return out;
}

Headers authentication_headers(const std::function<Headers()>& fresh_headers,
                               std::int64_t seconds) {
    auto headers = fresh_headers();
    for (const auto* key : {"X-Apple-I-MD",
                            "X-Apple-I-MD-M",
                            "X-Apple-I-MD-LU",
                            "X-Apple-I-MD-RINFO",
                            "X-Mme-Device-Id",
                            "X-MMe-Client-Info"}) {
        require(headers.contains(key) && !headers.at(key).empty(),
                std::string("Missing fresh anisette: ") + key);
    }
    headers["X-Apple-I-Client-Time"] = now(seconds);
    headers["Content-Type"] = "text/x-xml-plist";
    headers["Accept"] = "*/*";
    if (!headers.contains("User-Agent")) {
        headers["User-Agent"] = "iCloud/7.4";
    }
    return headers;
}

Json client_data(const Headers& headers) {
    Json data = {
        {"bootstrap", true},
        {"icscrec", true},
        {"loc", headers.contains("X-Apple-Locale") ? headers.at("X-Apple-Locale") : "en_US"},
        {"pbe", false},
        {"prkgen", true},
        {"svct", "iCloud"}};
    for (const auto* key : {"X-Apple-I-MD",
                            "X-Apple-I-MD-M",
                            "X-Apple-I-MD-LU",
                            "X-Apple-I-MD-RINFO",
                            "X-Mme-Device-Id",
                            "X-MMe-Client-Info",
                            "X-Apple-I-Client-Time",
                            "X-Apple-I-TimeZone",
                            "X-Apple-Locale"}) {
        data[key] = headers.contains(key) ? headers.at(key) : "";
    }
    const auto serial = headers.find("X-Apple-I-SRL-NO");
    if (serial != headers.end() && !serial->second.empty()) {
        data[serial->first] = serial->second;
    }
    return data;
}

bool trusted_device_code_already_sent(const Json& response, const Json& session) {
    const auto status = response.value("Status", Json::object());
    if (!status.value("au", std::string()).empty()) {
        return false;
    }
    // A no-au 409 already pushes a code; avoid a second notification.
    const auto session_status = session.value("status-code", std::int64_t(0));
    return session_status == 409 || ((session_status == 0 || session_status == 200) &&
                                     status.value("hsc", std::int64_t(0)) == 409);
}

Headers trusted_device_headers(Headers headers, const std::string& identity_token) {
    headers["X-Apple-Identity-Token"] = identity_token;
    apply_xcode_headers(headers);
    headers["Accept"] = "text/x-xml-plist";
    return headers;
}

} // namespace

Json parse_grandslam_session(View clear) {
    // SPD contains an XML dictionary fragment without a plist root.
    const std::string_view text(reinterpret_cast<const char*>(clear.data()), clear.size());
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first != std::string::npos && text.compare(first, 6, "<dict>") == 0) {
        auto wrapped = bytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">");
        wrapped.insert(wrapped.end(), clear.begin(), clear.end());
        const auto ending = bytes("</plist>");
        wrapped.insert(wrapped.end(), ending.begin(), ending.end());
        try {
            auto session = parse_plist(wrapped);
            crypto::wipe(wrapped.data(), wrapped.size());
            return session;
        } catch (...) {
            crypto::wipe(wrapped.data(), wrapped.size());
            throw;
        }
    }
    return parse_plist(clear);
}

AccountState grandslam_account_state(const Json& response, const Json& session) {
    const auto mode = response.value("Status", Json::object()).value("au", std::string());
    if (mode == "secondaryAuth") {
        return AccountState::requires_sms;
    }
    const auto session_status = session.value("status-code", std::int64_t(0));
    if (mode == "trustedDeviceSecondaryAuth" || session_status == 409 ||
        trusted_device_code_already_sent(response, session)) {
        return AccountState::requires_two_factor;
    }
    require(session_status == 0 || session_status == 200,
            "GrandSlam session rejected (status " + std::to_string(session_status) + ")");
    const auto tokens = session.value("t", Json::object());
    const auto pet = tokens.value("com.apple.gs.idms.pet", Json::object());
    require(pet.is_object() && pet.contains("token") && pet.at("token").is_string() &&
                !pet.at("token").get_ref<const std::string&>().empty(),
            "GrandSlam did not return a usable account token");
    return AccountState::authenticated;
}

void verify_grandslam_two_factor(const Json& response) {
    const auto& result = response.contains("Status") ? response.at("Status") : response;
    require(result.is_object() && result.contains("ec") && result.at("ec").is_number_integer() &&
                result.at("ec").get<std::int64_t>() == 0,
            "Apple did not confirm the 2FA code");
}

Json grandslam_login(const std::string& email,
                     const std::string& password,
                     const std::function<Headers()>& fresh_headers,
                     const std::function<std::string()>& two_factor,
                     const Transport& transport,
                     const std::function<std::int64_t()>& clock,
                     const VerificationOptions* verification) {
    auto http = [&](const std::string& url,
                    View body,
                    const Headers& headers,
                    const std::string& method = "POST") {
        return transport(HttpRequest{url, method, headers, Bytes(body.begin(), body.end())});
    };
    require(!email.empty() && !password.empty(), "Apple ID and password are required");
    const auto urls =
        lookup_grandslam_urls(authentication_headers(fresh_headers, clock()), transport);
    const auto service_url = grandslam_url(urls, "gsService");
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        Headers headers;
        auto post = [&](Json fields) {
            headers = authentication_headers(fresh_headers, clock());
            fields["cpd"] = client_data(headers);
            auto body = encode_plist(Json{{"Header", {{"Version", "1.0.1"}}}, {"Request", fields}});
            auto response = http(service_url, body, headers);
            require(response.status == 200, "GrandSlam HTTP " + std::to_string(response.status));
            const auto operation = fields.value("o", std::string("request"));

            Json top;
            try {
                top = parse_plist(response.body);
            } catch (const Error& error) {
                throw Error("GrandSlam " + operation + " response: " + error.what());
            }
            require(top.contains("Response") && top["Response"].is_object(),
                    "Malformed GrandSlam response");
            auto result = top["Response"];
            try {
                status(result);
            } catch (const Error& error) {
                throw Error("GrandSlam " + fields.value("o", std::string("request")) + ": " +
                            error.what());
            }
            return result;
        };
        SrpHandshake srp;
        auto initial = post({{"A2k", Json::binary(srp.public_key())},
                             {"o", "init"},
                             {"ps", {"s2k", "s2k_fo"}},
                             {"u", email}});
        require(initial.contains("i") && initial["i"].is_number_integer(),
                "Missing SRP iteration count");
        auto iterations = initial["i"].get<std::int64_t>();
        require(iterations > 0 && iterations <= 1000000, "Invalid SRP iteration count");
        auto proof = srp.complete(email,
                                  password,
                                  binary(initial, "s"),
                                  binary(initial, "B"),
                                  int(iterations),
                                  text(initial, "sp"));
        auto complete = post({{"M1", Json::binary(proof.m1)},
                              {"c", text(initial, "c")},
                              {"o", "complete"},
                              {"u", email}});
        proof.verify(binary(complete, "M2"));
        auto key = hmac_sha256(proof.key, bytes("extra data key:")),
             iv = hmac_sha256(proof.key, bytes("extra data iv:"));
        iv.resize(16);
        auto clear = aes_cbc(binary(complete, "spd"), key, iv, true, true);

        Json session;
        try {
            session = parse_grandslam_session(clear);
        } catch (const Error& error) {
            crypto::wipe(clear.data(), clear.size());
            crypto::wipe(proof.key.data(), proof.key.size());
            throw Error("GrandSlam decrypted session: " + std::string(error.what()));
        }
        crypto::wipe(clear.data(), clear.size());
        crypto::wipe(proof.key.data(), proof.key.size());
        const auto account_state = grandslam_account_state(complete, session);
        if (account_state == AccountState::authenticated) {
            return session;
        }
        require(attempt == 0, "Apple requested verification again after 2FA");
        require(bool(two_factor), "Two-factor verification requires a callback");
        const auto identity_token =
            base64(bytes(text(session, "adsid") + ":" + text(session, "GsIdmsToken")));
        const auto selected_method =
            verification ? verification->method : VerificationMethod::automatic;
        const auto use_sms = selected_method == VerificationMethod::sms ||
                             (selected_method == VerificationMethod::automatic &&
                              account_state == AccountState::requires_sms);
        require(use_sms || account_state != AccountState::requires_sms,
                "Apple requires SMS verification; choose SMS or automatic verification");
        if (use_sms) {
            const auto secondary_url = grandslam_url(urls, "secondaryAuth");
            auto sms_headers = trusted_device_headers(
                authentication_headers(fresh_headers, clock()), identity_token);
            sms_headers["Content-Type"] = "application/json";
            sms_headers["Accept"] = "application/json";
            std::int64_t phone_id = verification ? verification->phone_number_id : 0;
            bool already_sent = false;
            if (phone_id <= 0) {
                const auto configuration = http(secondary_url, {}, sms_headers, "GET");
                require(configuration.status == 200 || configuration.status == 201,
                        "Cannot read SMS verification configuration (HTTP " +
                            std::to_string(configuration.status) + ")");
                const auto data = Json::parse(configuration.body);
                const auto& container = data.contains("phoneNumberVerification")
                                            ? data.at("phoneNumberVerification")
                                            : data;
                const auto& phones = container.at("trustedPhoneNumbers");
                require(phones.is_array() && !phones.empty() && phones.size() <= 32,
                        "No trusted SMS phone numbers are available");
                std::vector<TrustedPhoneNumber> choices;
                for (const auto& phone : phones) {
                    const auto id = phone.at("id").get<std::int64_t>();
                    require(id > 0, "Invalid trusted phone identifier");
                    choices.push_back({id, phone.value("numberWithDialCode", std::string())});
                }
                if (verification && verification->select_phone) {
                    phone_id = verification->select_phone(choices);
                } else {
                    require(
                        choices.size() == 1,
                        "Multiple SMS numbers are available; provide a phone-selection callback");
                    phone_id = choices.front().id;
                }
                require(std::any_of(choices.begin(),
                                    choices.end(),
                                    [&](const auto& phone) {
                                        return phone.id == phone_id;
                                    }),
                        "SMS phone selection was canceled or is invalid");
                already_sent = configuration.status == 201 && phone_id == choices.front().id;
            }
            if (!already_sent) {
                const auto payload =
                    bytes(Json{{"phoneNumber", {{"id", phone_id}}}, {"mode", "sms"}}.dump());
                const auto delivery =
                    http(secondary_url + "/verify/phone", payload, sms_headers, "PUT");
                require(delivery.status == 200 || delivery.status == 201,
                        "Cannot request SMS verification (HTTP " + std::to_string(delivery.status) +
                            ")");
            }
            auto code = two_factor();
            code.erase(std::remove_if(code.begin(),
                                      code.end(),
                                      [](unsigned char byte) {
                                          return std::isspace(byte);
                                      }),
                       code.end());

            struct WipeCode {
                std::string& value;

                ~WipeCode() {
                    crypto::wipe(value.data(), value.size());
                }
            } wipe{code};

            require(code.size() == 6 && code.find_first_not_of("0123456789") == std::string::npos,
                    "2FA must contain six digits");
            const auto payload = bytes(Json{{"phoneNumber", {{"id", phone_id}}},
                                            {"mode", "sms"},
                                            {"securityCode", {{"code", code}}}}
                                           .dump());
            sms_headers = trusted_device_headers(authentication_headers(fresh_headers, clock()),
                                                 identity_token);
            sms_headers["Content-Type"] = "application/json";
            sms_headers["Accept"] = "application/json";
            const auto verified =
                http(secondary_url + "/verify/phone/securitycode", payload, sms_headers);
            const auto confirmed = std::any_of(
                verified.headers.begin(), verified.headers.end(), [](const auto& field) {
                    auto name = field.first;
                    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
                        return char(std::tolower(c));
                    });
                    return name == "x-apple-pe-token" && !field.second.empty();
                });
            require(verified.status == 200 && confirmed,
                    "Apple did not confirm the SMS code (HTTP " +
                        std::to_string(verified.status) + ")");
            continue;
        }
        if (!trusted_device_code_already_sent(complete, session)) {
            const auto trusted = trusted_device_headers(headers, identity_token);
            const auto trigger =
                http(grandslam_url(urls, "trustedDeviceSecondaryAuth"), {}, trusted, "GET");
            require(trigger.status == 200, "Could not request trusted-device verification");
        }
        auto code = two_factor();
        code.erase(std::remove_if(code.begin(),
                                  code.end(),
                                  [](unsigned char c) {
                                      return std::isspace(c);
                                  }),
                   code.end());
        require(code.size() == 6 && code.find_first_not_of("0123456789") == std::string::npos,
                "2FA must contain six digits");
        auto trusted =
            trusted_device_headers(authentication_headers(fresh_headers, clock()), identity_token);
        trusted["security-code"] = code;
        auto verified = http(grandslam_url(urls, "validateCode"), {}, trusted, "GET");
        crypto::wipe(code.data(), code.size());
        trusted.erase("security-code");

        require(verified.status == 200,
                "2FA request failed (HTTP " + std::to_string(verified.status) + ")");
        auto result = parse_plist(verified.body);
        verify_grandslam_two_factor(result);
    }
    throw Error("GrandSlam authentication did not complete");
}

DeveloperSession exchange_developer_session(const AccountSession& account,
                                            const std::function<Headers()>& fresh_headers,
                                            const Transport& transport,
                                            const std::function<std::int64_t()>& clock) {
    constexpr const char* application = "com.apple.gs.xcode.auth";
    const auto session = parse_plist(account.plist);
    require(text(session, "adsid") == account.account_id,
            "Account session identifier does not match its authenticated data");
    require(grandslam_account_state(Json::object(), session) == AccountState::authenticated,
            "Complete two-factor authentication before requesting Developer Session");
    auto key = binary(session, "sk");

    struct WipeKey {
        Bytes& value;

        ~WipeKey() {
            crypto::wipe(value.data(), value.size());
        }
    } wipe_key{key};

    require(key.size() == 32, "Account session does not contain a 32-byte application-token key");
    const auto challenge = binary(session, "c");
    require(!challenge.empty() && challenge.size() <= 4096, "Invalid application-token challenge");
    auto headers = authentication_headers(fresh_headers, clock());
    apply_xcode_headers(headers);
    const auto checksum =
        hmac_sha256(key, bytes(std::string("apptokens") + account.account_id + application));
    const Json fields = {{"o", "apptokens"},
                         {"u", account.account_id},
                         {"app", {application}},
                         {"c", Json::binary(challenge)},
                         {"t", text(session, "GsIdmsToken")},
                         {"checksum", Json::binary(checksum)},
                         {"cpd", client_data(headers)}};
    const auto body = encode_plist(Json{{"Header", {{"Version", "1.0.1"}}}, {"Request", fields}});
    const auto response =
        transport(HttpRequest{"https://gsa.apple.com/grandslam/GsService2", "POST", headers, body});
    require(response.status == 200, "Developer Session HTTP " + std::to_string(response.status));
    const auto envelope = parse_plist(response.body);
    const auto& result = envelope.at("Response");
    status(result);
    const auto encrypted = binary(result, "et");
    require(encrypted.size() > 35 && encrypted.size() <= 1024 * 1024 &&
                std::equal(encrypted.begin(), encrypted.begin() + 3, "XYZ"),
            "Invalid encrypted application-token envelope");
    crypto::Context<mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free> cipher;
    crypto::check(mbedtls_gcm_setkey(cipher.get(), MBEDTLS_CIPHER_ID_AES, key.data(), 256),
                  "Cannot initialize application-token cipher");
    Bytes clear(encrypted.size() - 35);

    struct WipeClear {
        Bytes& value;

        ~WipeClear() {
            crypto::wipe(value.data(), value.size());
        }
    } wipe_clear{clear};

    require(mbedtls_gcm_auth_decrypt(cipher.get(),
                                     clear.size(),
                                     encrypted.data() + 3,
                                     16,
                                     encrypted.data(),
                                     3,
                                     encrypted.data() + encrypted.size() - 16,
                                     16,
                                     encrypted.data() + 19,
                                     clear.data()) == 0,
            "Application-token authentication failed");
    const auto decoded = parse_grandslam_session(clear);
    const auto& token = decoded.at("t").at(application);
    const auto expiry = token.value("expiry", std::int64_t(0));
    require(expiry >= 0 && (!expiry || clock() < expiry / 1000), "Developer Session has expired");
    return {account.account_id, text(token, "token"), expiry};
}

} // namespace apple_auth::netdetail
