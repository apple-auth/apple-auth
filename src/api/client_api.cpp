#include "client/client_internal.hpp"
#include "client/state_storage.hpp"
#include "crypto/backend.hpp"
#include <apple_auth/client_c_api.h>
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
#include <apple_auth/appstore.hpp>
#include <apple_auth/testflight.hpp>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>

using namespace apple_auth;

struct aauth_client {
    Client value;
};

struct aauth_account_session {
    AccountSession value;
};

struct aauth_store_session {
    StoreSession value;
};

struct aauth_store_client {
    StoreClient value;
};
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
struct aauth_testflight_client {
    TestFlightClient value;
};
struct aauth_appstore_ios_client {
    AppStoreIosClient value;
};
struct aauth_appstore_mac_client {
    AppStoreMacClient value;
};
#else
struct aauth_testflight_client {};
struct aauth_appstore_ios_client {};
struct aauth_appstore_mac_client {};
#endif

namespace {
thread_local std::array<char, 512> last_error{};
constexpr std::size_t maximum_response_size = 16 * 1024 * 1024;

void require(bool valid) {
    if (!valid) {
        throw apple_auth::Error(ErrorCode::invalid_argument, "Invalid client argument or buffer");
    }
}

void set_error(const char* message) noexcept {
    const auto size = std::min(std::strlen(message), last_error.size() - 1);
    std::copy_n(message, size, last_error.begin());
    last_error[size] = '\0';
}

template <class Operation> aauth_status guard(Operation&& operation) noexcept {
    try {
        last_error[0] = '\0';
        operation();
        return AAUTH_OK;
    } catch (const apple_auth::Error& error) {
        set_error(error.what());
        return static_cast<aauth_status>(error.code());
    } catch (const std::exception& error) {
        set_error(error.what());
        return AAUTH_INTERNAL_ERROR;
    } catch (...) {
        set_error("Unknown client failure");
        return AAUTH_INTERNAL_ERROR;
    }
}

std::filesystem::path utf8_path(const char* value) {
    require(value != nullptr && *value != '\0');
    const std::string_view text(value);
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

TwoFactor make_two_factor(aauth_two_factor_callback callback, void* context) {
    if (!callback) {
        return {};
    }
    return [callback, context] {
        struct Code {
            std::array<char, 64> bytes{};
            ~Code() {
                crypto::wipe(bytes.data(), bytes.size());
            }
        } code;
        std::size_t size = 0;
        if (callback(context, code.bytes.data(), code.bytes.size(), &size) != 0) {
            throw apple_auth::Error(ErrorCode::authentication, "Verification callback canceled");
        }
        require(size <= code.bytes.size());
        return std::string(code.bytes.data(), size);
    };
}

void copy_buffer(ByteView bytes, aauth_client_buffer* output) {
    require(output != nullptr);
    auto data = bytes.empty() ? nullptr : std::make_unique<std::uint8_t[]>(bytes.size());
    if (!bytes.empty()) {
        std::copy(bytes.begin(), bytes.end(), data.get());
    }
    *output = {data.release(), bytes.size()};
}

ClientOptions client_options(const aauth_client_options* supplied) {
    const auto options = supplied ? *supplied : aauth_client_options{};
    ClientOptions config;
    if (options.clock) config.clock = [options] { return options.clock(options.context); };
    auto fallback = options.transport ? Transport{} : netdetail::make_curl_transport();
    config.transport = [options, fallback = std::move(fallback)](const HttpRequest& request) {
        const auto start = std::chrono::steady_clock::now();
        const auto observe = [&](long status) {
            if (options.observer) {
                options.observer(options.context, request.method.c_str(), request.url.c_str(), status,
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
            }
        };
        HttpResponse result;
        try {
            if (options.transport) {
                const auto json = netdetail::Json(request.headers).dump();
                const aauth_http_request input{request.url.c_str(), request.method.c_str(), json.c_str(),
                                               request.body.data(), request.body.size()};
                aauth_http_response response{};
                struct Owner {
                    aauth_http_response& response;
                    ~Owner() {
                        delete[] response.body.data;
                        delete[] response.headers_json.data;
                    }
                } owner{response};
                if (options.transport(options.context, &input, &response) != 0)
                    throw apple_auth::Error(ErrorCode::network, "HTTP transport callback failed");
                require(response.body.size <= maximum_response_size && (!response.body.size || response.body.data) &&
                        response.headers_json.size <= 64 * 1024 && (!response.headers_json.size || response.headers_json.data));
                result.status = response.status;
                if (response.body.size) result.body.assign(response.body.data, response.body.data + response.body.size);
                if (response.headers_json.size) {
                    const auto headers = netdetail::Json::parse(response.headers_json.data,
                        response.headers_json.data + response.headers_json.size);
                    require(headers.is_array() && headers.size() <= 1024);
                    for (const auto& item : headers) {
                        require(item.is_array() && item.size() == 2 && item[0].is_string() && item[1].is_string());
                        result.headers.emplace_back(item[0].get<std::string>(), item[1].get<std::string>());
                    }
                }
            } else result = fallback(request);
        } catch (...) { observe(0); throw; }
        observe(result.status);
        return result;
    };
    return config;
}

Headers parse_headers(const char *encoded) {
    if (!encoded) {
        return {};
    }
    require(std::strlen(encoded) <= 65536);
    const auto json = netdetail::Json::parse(encoded);
    require(json.is_object());
    return json.get<Headers>();
}

ClientOptions store_options(const aauth_client_options *supplied,
                            const aauth_device_headers *headers, const char *headers_json) {
    auto options = client_options(supplied);
    if (headers) {
        options.user_agent = headers->user_agent ? headers->user_agent : "";
        options.client_info = headers->client_info ? headers->client_info : "";
    }
    options.headers = parse_headers(headers_json);
    netdetail::validate_device_headers(options);
    return options;
}

HttpRequest read_request(const aauth_http_request *input) {
    require(input && input->url && input->method && input->body_size <= 1024 * 1024 &&
            (!input->body_size || input->body));
    HttpRequest request{input->url, input->method, parse_headers(input->headers_json), {}};
    if (input->body_size) {
        request.body.assign(input->body, input->body + input->body_size);
    }
    return request;
}

void write_json(const netdetail::Json &value, aauth_client_buffer *output) {
    copy_buffer(netdetail::bytes(value.dump()), output);
}

void write_response(const HttpResponse &response, aauth_client_buffer *output) {
    write_json({{"status", response.status},
                {"body", base64(response.body)},
                {"headers", response.headers}},
               output);
}

#ifdef APPLE_AUTH_WITH_TESTFLIGHT
ByteView json_input(const std::uint8_t *data, std::size_t size) {
    require(data && size && size <= 1024 * 1024);
    return {data, size};
}

TestFlightOptions testflight_options(const char *encoded) {
    if (!encoded) {
        return {};
    }
    require(std::strlen(encoded) <= 65536);
    const auto json = netdetail::Json::parse(encoded);
    require(json.is_object());
    return {json.value("headers", Headers{}), json.value("deviceModel", std::string{}),
            json.value("deviceName", std::string{})};
}

netdetail::Json archive_info(const TestFlightArchiveInfo &info) {
    return {{"bundle", info.bundle},
            {"members", info.members},
            {"encrypted_images", info.encrypted_images},
            {"clear_images", info.clear_images}};
}

std::string path_string(const std::filesystem::path &path) {
    const auto text = path.u8string();
    return {text.begin(), text.end()};
}
#endif
} // namespace

extern "C" {
const char* aauth_client_version(void) {
    return version();
}

const char* aauth_client_last_error(void) {
    return last_error.data();
}

aauth_status aauth_client_create(const aauth_client_config* supplied, aauth_client** output) {
    return guard([&] {
        require(output != nullptr);
        const auto input = supplied ? *supplied : aauth_client_config{};
        require(input.platform >= AAUTH_DEVICE_AUTOMATIC && input.platform <= AAUTH_DEVICE_ANDROID &&
                input.state_size <= netdetail::maximum_state_size && (!input.state_size || input.state) &&
                !(input.directory && (input.state || input.state_size)));
        auto options = store_options(input.options, input.headers, input.headers_json);
        options.device_platform = static_cast<DevicePlatform>(input.platform);
        if (input.mac_device) {
            const auto& mac = *input.mac_device;
            options.mac_device = {mac.model ? mac.model : "", mac.macos_version ? mac.macos_version : "",
                                   mac.macos_build ? mac.macos_build : ""};
        }
        if (input.iphone_device) {
            const auto& phone = *input.iphone_device;
            options.iphone_device = {phone.model ? phone.model : "", phone.ios_version ? phone.ios_version : "",
                                      phone.ios_build ? phone.ios_build : ""};
        }
        if (input.serial_number) options.serial_number = input.serial_number;
        auto create = [&]() -> Client {
            if (input.directory) return Client(utf8_path(input.directory), std::move(options));
            if (input.state || input.state_size) return Client(ByteView(input.state, input.state_size), std::move(options));
            return Client(std::move(options));
        };
        auto result = std::make_unique<aauth_client>(aauth_client{create()});
        *output = result.release();
    });
}

aauth_status aauth_client_state(const aauth_client* client, aauth_client_buffer* output) {
    return guard([&] { require(client && output); copy_buffer(client->value.serialize_state(), output); });
}

aauth_status aauth_client_session_data(const aauth_client* client, aauth_session_kind kind,
                                      aauth_client_buffer* output) {
    return guard([&] {
        require(client && output && (kind == AAUTH_SESSION_ACCOUNT || kind == AAUTH_SESSION_STORE));
        copy_buffer(client->value.session_data(static_cast<SessionKind>(kind)), output);
    });
}

aauth_status aauth_client_set_session_data(aauth_client* client, aauth_session_kind kind,
                                          const uint8_t* data, size_t size) {
    return guard([&] {
        require(client && size <= netdetail::maximum_state_size && (!size || data) &&
                (kind == AAUTH_SESSION_ACCOUNT || kind == AAUTH_SESSION_STORE));
        client->value.set_session_data({data, size}, static_cast<SessionKind>(kind));
    });
}

aauth_status aauth_client_mac_device(const aauth_client* client, aauth_client_buffer* output) {
    return guard([&] {
        require(client != nullptr && output != nullptr);
        netdetail::Json metadata = nullptr;
        if (client->value.device_platform() == DevicePlatform::mac) {
            const auto device = client->value.mac_device();
            metadata = {{"model", device.model},
                        {"macos_version", device.macos_version},
                        {"macos_build", device.macos_build}};
        }
        const auto json = metadata.dump();
        copy_buffer({reinterpret_cast<const std::uint8_t*>(json.data()), json.size()}, output);
    });
}

aauth_status aauth_client_device_platform(const aauth_client* client,
                                          aauth_device_platform* output) {
    return guard([&] {
        require(client != nullptr && output != nullptr);
        *output = static_cast<aauth_device_platform>(client->value.device_platform());
    });
}

aauth_status aauth_client_device_info(const aauth_client* client, aauth_client_buffer* output) {
    return guard([&] {
        require(client != nullptr && output != nullptr);
        constexpr const char* platforms[] = {"automatic", "windows", "mac", "iphone", "android"};
        const auto platform = client->value.device_platform();
        const auto serial = client->value.serial_number();
        netdetail::Json info = {
            {"platform", platforms[static_cast<unsigned>(platform)]},
            {"serial_number", serial.empty() ? netdetail::Json(nullptr) : netdetail::Json(serial)}};
        if (platform == DevicePlatform::mac) {
            const auto mac = client->value.mac_device();
            info["model"] = mac.model;
            info["os_version"] = mac.macos_version;
            info["os_build"] = mac.macos_build;
        } else if (platform == DevicePlatform::iphone) {
            const auto iphone = client->value.iphone_device();
            info["model"] = iphone.model;
            info["os_version"] = iphone.ios_version;
            info["os_build"] = iphone.ios_build;
        }
        const auto json = info.dump();
        copy_buffer({reinterpret_cast<const std::uint8_t*>(json.data()), json.size()}, output);
    });
}

void aauth_client_free(aauth_client* client) {
    delete client;
}

aauth_status aauth_client_provision(aauth_client* client) {
    return guard([&] {
        require(client != nullptr);
        client->value.provision();
    });
}

aauth_status aauth_client_headers(aauth_client* client, aauth_client_buffer* output) {
    return guard([&] {
        require(client != nullptr && output != nullptr);
        const auto json = netdetail::Json(client->value.headers()).dump();
        copy_buffer({reinterpret_cast<const std::uint8_t*>(json.data()), json.size()}, output);
    });
}

void aauth_account_session_free(aauth_account_session* session) {
    delete session;
}

aauth_status aauth_account_session_from_plist(const std::uint8_t* data,
                                              std::size_t size,
                                              aauth_account_session** output) {
    return guard([&] {
        require(data && size && size <= maximum_response_size && output);
        const auto session = netdetail::parse_plist({data, size});
        require(netdetail::grandslam_account_state(netdetail::Json::object(), session) ==
                netdetail::AccountState::authenticated);
        auto result = std::make_unique<aauth_account_session>(aauth_account_session{
            {session.at("adsid").get<std::string>(),
             session.at("t").at("com.apple.gs.idms.pet").at("token").get<std::string>(),
             Bytes(data, data + size)}});
        *output = result.release();
    });
}

aauth_status aauth_client_login(aauth_client* client,
                                   const char* email,
                                   const char* password,
                                   const aauth_verification_options* supplied,
                                   aauth_account_session** output) {
    return guard([&] {
        require(client && email && password && output);
        VerificationOptions verification;
        if (supplied) {
            const auto options = *supplied;
            require(options.method >= AAUTH_VERIFY_AUTOMATIC &&
                    options.method <= AAUTH_VERIFY_SMS && options.phone_number_id >= 0);
            verification.method = static_cast<VerificationMethod>(options.method);
            verification.phone_number_id = options.phone_number_id;
            verification.code = make_two_factor(options.code, options.context);
            if (options.select_phone) {
                verification.select_phone = [options](const auto& phones) {
                    netdetail::Json choices = netdetail::Json::array();
                    for (const auto& phone : phones) {
                        choices.push_back(
                            {{"id", phone.id}, {"display_number", phone.display_number}});
                    }
                    const auto json = choices.dump();
                    std::int64_t selected = 0;
                    if (options.select_phone(options.context, json.c_str(), &selected) != 0) {
                        throw apple_auth::Error(ErrorCode::authentication,
                                                "SMS phone selection canceled");
                    }
                    return selected;
                };
            }
        }
        auto result = std::make_unique<aauth_account_session>(
            aauth_account_session{client->value.login_with_options(email, password, verification)});
        *output = result.release();
    });
}

aauth_status aauth_client_developer_session(aauth_client* client,
                                            const aauth_account_session* account,
                                            aauth_client_buffer* output) {
    return guard([&] {
        require(client && account && output);
        const auto session = client->value.developer_session(account->value);
        copy_buffer(netdetail::bytes(netdetail::Json{{"account_id", session.account_id},
                                                     {"token", session.token},
                                                     {"expires_at_ms", session.expires_at_ms}}
                                         .dump()),
                    output);
    });
}

aauth_status aauth_client_developer_headers(aauth_client* client,
                                            const char* account_id,
                                            const char* token,
                                            std::int64_t expires_at_ms,
                                            aauth_client_buffer* output) {
    return guard([&] {
        require(client && account_id && token && output);
        const auto headers = client->value.developer_headers({account_id, token, expires_at_ms});
        copy_buffer(netdetail::bytes(netdetail::Json(headers).dump()), output);
    });
}

aauth_status aauth_account_session_save(const aauth_account_session* session,
                                        const char* filename) {
    return guard([&] {
        require(session != nullptr);
        session->value.save(utf8_path(filename));
    });
}

aauth_status aauth_account_session_plist(const aauth_account_session* session,
                                         aauth_client_buffer* output) {
    return guard([&] {
        require(session != nullptr);
        copy_buffer(session->value.plist, output);
    });
}

aauth_status aauth_client_buffer_alloc(std::size_t size, aauth_client_buffer* output) {
    return guard([&] {
        require(output != nullptr && size <= maximum_response_size);
        auto data = size ? std::make_unique<std::uint8_t[]>(size) : nullptr;
        *output = {data.release(), size};
    });
}

aauth_status aauth_client_store_provision(aauth_client* client) {
    return guard([&] {
        require(client);
        client->value.provision_store();
    });
}

aauth_status aauth_client_store_headers(aauth_client* client, aauth_client_buffer* output) {
    return guard([&] {
        require(client && output);
        copy_buffer(netdetail::bytes(netdetail::Json(client->value.store_headers()).dump()),
                    output);
    });
}

aauth_status aauth_client_store_login(aauth_client* client,
                                      const char* email,
                                      const char* password,
                                      aauth_two_factor_callback callback,
                                      void* context,
                                      aauth_store_session** output) {
    return guard([&] {
        require(client && email && password && output);
        auto result = std::make_unique<aauth_store_session>(aauth_store_session{
            client->value.login_store(email, password, make_two_factor(callback, context))});
        *output = result.release();
    });
}

void aauth_store_session_free(aauth_store_session* session) {
    delete session;
}

aauth_status aauth_store_session_load(const char* filename, aauth_store_session** output) {
    return guard([&] {
        require(output);
        auto result = std::make_unique<aauth_store_session>(
            aauth_store_session{StoreSession::load(utf8_path(filename))});
        *output = result.release();
    });
}

aauth_status aauth_store_session_from_plist(const std::uint8_t* data,
                                            std::size_t size,
                                            aauth_store_session** output) {
    return guard([&] {
        require(output && data && size && size <= 1024 * 1024);
        auto result = std::make_unique<aauth_store_session>(
            aauth_store_session{StoreSession::from_plist({data, size})});
        *output = result.release();
    });
}

aauth_status aauth_store_session_save(const aauth_store_session* session, const char* filename) {
    return guard([&] {
        require(session);
        session->value.save(utf8_path(filename));
    });
}

aauth_status aauth_store_session_plist(const aauth_store_session* session,
                                       aauth_client_buffer* output) {
    return guard([&] {
        require(session && output);
        copy_buffer(session->value.plist(), output);
    });
}

aauth_status aauth_store_session_info(const aauth_store_session* session,
                                      aauth_client_buffer* output) {
    return guard([&] {
        require(session && output);
        copy_buffer(netdetail::bytes(netdetail::Json{{"account_id", session->value.account_id()},
                                                     {"storefront", session->value.storefront()},
                                                     {"protocol", static_cast<int>(session->value.protocol())}}
                                         .dump()),
                    output);
    });
}

aauth_status aauth_store_session_headers(const aauth_store_session* session,
                                         const char* url,
                                         aauth_client_buffer* output) {
    return guard([&] {
        require(session && url && output);
        copy_buffer(netdetail::bytes(netdetail::Json(session->value.headers(url)).dump()), output);
    });
}

aauth_status aauth_client_store_request(aauth_client* client,
                                        aauth_store_session* session,
                                        const aauth_http_request* input,
                                        aauth_client_buffer* output) {
    return guard([&] {
        require(client && session && input && output && input->url && input->method &&
                input->headers_json && input->body_size <= 1024 * 1024 &&
                (!input->body_size || input->body));
        HttpRequest request{input->url,
                            input->method,
                            netdetail::Json::parse(input->headers_json).get<Headers>(),
                            {}};
        if (input->body_size) {
            request.body.assign(input->body, input->body + input->body_size);
        }
        const auto response = client->value.store_request(session->value, std::move(request));
        copy_buffer(netdetail::bytes(netdetail::Json{{"status", response.status},
                                                     {"body", base64(response.body)},
                                                     {"headers", response.headers}}
                                         .dump()),
                    output);
    });
}

void aauth_client_buffer_free(aauth_client_buffer* buffer) {
    if (buffer) {
        if (buffer->data) {
            crypto::wipe(buffer->data, buffer->size);
        }
        delete[] buffer->data;
        *buffer = {};
    }
}
aauth_status aauth_client_generate_session_key(aauth_client_buffer* output) {
    return guard([&] {
        require(output);
        auto key = generate_session_key();
        struct Wipe { Bytes& value; ~Wipe() { crypto::wipe(value.data(), value.size()); } } wipe{key};
        copy_buffer(key, output);
    });
}
aauth_status aauth_client_encrypt_session(const uint8_t* data, size_t size,
    const uint8_t* key, size_t key_size, aauth_client_buffer* output) {
    return guard([&] {
        require(output && (data || !size) && key && size <= maximum_response_size);
        copy_buffer(encrypt_session({data, size}, {key, key_size}), output);
    });
}
aauth_status aauth_client_decrypt_session(const uint8_t* data, size_t size,
    const uint8_t* key, size_t key_size, aauth_client_buffer* output) {
    return guard([&] {
        require(output && data && key && size <= maximum_response_size + session_encryption_overhead);
        auto clear = decrypt_session({data, size}, {key, key_size});
        struct Wipe { Bytes& value; ~Wipe() { crypto::wipe(value.data(), value.size()); } } wipe{clear};
        copy_buffer(clear, output);
    });
}
aauth_status aauth_client_save_session(const char* filename, const uint8_t* data, size_t size) {
    return guard([&] {
        require((data || !size) && size <= maximum_response_size + session_encryption_overhead);
        netdetail::write_private(utf8_path(filename), {data, size});
    });
}
aauth_status aauth_client_features(aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        constexpr bool downloads = true;
#else
        constexpr bool downloads = false;
#endif
        write_json({{"store_protocols", true}, {"downloads", downloads}, {"session_encryption", true}}, output);
    });
}

aauth_status aauth_store_client_create(const char *directory, aauth_store_protocol protocol,
                                       const aauth_client_options *options,
                                       const aauth_device_headers *headers,
                                       const char *headers_json, aauth_store_client **output) {
    return guard([&] {
        require(output && protocol >= AAUTH_STORE_ANDROID_MUSIC &&
                protocol <= AAUTH_STORE_CONFIGURATOR);
        auto result = std::make_unique<aauth_store_client>(aauth_store_client{
            StoreClient(utf8_path(directory), static_cast<StoreProtocol>(protocol),
                        store_options(options, headers, headers_json))});
        *output = result.release();
    });
}

void aauth_store_client_free(aauth_store_client *client) { delete client; }

aauth_status aauth_store_client_provision(aauth_store_client *client) {
    return guard([&] {
        require(client);
        client->value.provision();
    });
}

aauth_status aauth_store_client_headers(aauth_store_client *client, aauth_client_buffer *output) {
    return guard([&] {
        require(client && output);
        write_json(client->value.headers(), output);
    });
}

aauth_status aauth_store_client_login(aauth_store_client *client, const char *email,
                                      const char *password, aauth_two_factor_callback callback,
                                      void *context, aauth_store_session **output) {
    return guard([&] {
        require(client && email && password && output);
        auto result = std::make_unique<aauth_store_session>(aauth_store_session{
            client->value.login(email, password, make_two_factor(callback, context))});
        *output = result.release();
    });
}

aauth_status aauth_client_store_login_with_pet(aauth_client *client, const char *email,
                                               const aauth_account_session *account,
                                               aauth_store_session **output) {
    return guard([&] {
        require(client && email && account && output);
        auto result = std::make_unique<aauth_store_session>(
            aauth_store_session{client->value.login_store_with_pet(email, account->value)});
        *output = result.release();
    });
}

aauth_status aauth_store_client_login_with_pet(aauth_store_client *client, const char *email,
                                               const aauth_account_session *account,
                                               aauth_client *device, aauth_store_session **output) {
    return guard([&] {
        require(client && email && account && device && output);
        require(device->value.device_platform() == DevicePlatform::mac);
        auto result =
            std::make_unique<aauth_store_session>(aauth_store_session{client->value.login_with_pet(
                email, account->value, [&] { return device->value.headers(); })});
        *output = result.release();
    });
}

aauth_status aauth_store_client_request(aauth_store_client *client, aauth_store_session *session,
                                        const aauth_http_request *request,
                                        aauth_client_buffer *output) {
    return guard([&] {
        require(client && session && output);
        write_response(client->value.request(session->value, read_request(request)), output);
    });
}

aauth_status aauth_store_session_ios_context(const aauth_store_session *session,
                                             const char *country, aauth_client_buffer *output) {
    return guard([&] {
        require(session && country && output);
        copy_buffer(session->value.ios_context(country), output);
    });
}

aauth_status aauth_store_session_testflight_context(const aauth_store_session *session,
                                                    const std::uint8_t *hardware20,
                                                    std::size_t size, const char *headers_json,
                                                    aauth_client_buffer *output) {
    return guard([&] {
        require(session && hardware20 && size == 20 && output);
        copy_buffer(
            session->value.testflight_context({hardware20, size}, parse_headers(headers_json)),
            output);
    });
}

aauth_status aauth_testflight_client_create(const uint8_t *data, size_t size,
                                            const aauth_client_options *transport,
                                            const char *options_json,
                                            aauth_testflight_client **output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(output);
        auto result = std::make_unique<aauth_testflight_client>(aauth_testflight_client{
            TestFlightClient(json_input(data, size), client_options(transport).transport,
                             testflight_options(options_json))});
        *output = result.release();
#else
        (void)data;
        (void)size;
        (void)transport;
        (void)options_json;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_from_store_cookies(const uint8_t *data, size_t size,
                                                        const aauth_client_options *transport,
                                                        const char *options_json,
                                                        aauth_testflight_client **output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(output);
        auto result = std::make_unique<aauth_testflight_client>(aauth_testflight_client{
            TestFlightClient::from_store_cookies(json_input(data, size),
                                                 client_options(transport).transport,
                                                 testflight_options(options_json))});
        *output = result.release();
#else
        (void)data;
        (void)size;
        (void)transport;
        (void)options_json;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_serialize(const aauth_testflight_client *client,
                                               aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && output);
        copy_buffer(client->value.serialize(), output);
#else
        (void)client;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported, "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_save(const aauth_testflight_client *client, const char *path) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client);
        client->value.save(utf8_path(path));
#else
        (void)client;
        (void)path;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_catalog(aauth_testflight_client *client,
                                             aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && output);
        copy_buffer(client->value.catalog(), output);
#else
        (void)client;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_install_metadata(aauth_testflight_client *client,
                                                      const char *bundle,
                                                      aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && bundle && output);
        copy_buffer(client->value.install_metadata(bundle), output);
#else
        (void)client;
        (void)bundle;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_testflight_client_download_ipa(aauth_testflight_client *client, const char *bundle,
                                              const char *path, int include_sinf,
                                              aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && bundle && output && (include_sinf == 0 || include_sinf == 1));
        const auto result = client->value.download(bundle, utf8_path(path), include_sinf != 0);
        write_json({{"archive", archive_info(result.archive)},
                    {"downloaded_bytes", result.downloaded_bytes},
                    {"artifacts", path_string(result.artifacts)}},
                   output);
#else
        (void)client;
        (void)bundle;
        (void)path;
        (void)include_sinf;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_ios_client_create(const uint8_t *data, size_t size,
                                              const aauth_client_options *transport,
                                              const char *headers_json,
                                              aauth_appstore_ios_client **output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(output);
        auto result = std::make_unique<aauth_appstore_ios_client>(aauth_appstore_ios_client{
            AppStoreIosClient(json_input(data, size), client_options(transport).transport,
                              parse_headers(headers_json))});
        *output = result.release();
#else
        (void)data;
        (void)size;
        (void)transport;
        (void)headers_json;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_ios_client_catalog(aauth_appstore_ios_client *client, uint64_t app_id,
                                               aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        copy_buffer(client->value.catalog(app_id), output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_ios_client_metadata(aauth_appstore_ios_client *client, uint64_t app_id,
                                                aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        copy_buffer(client->value.metadata(app_id), output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_ios_client_acquire_free(aauth_appstore_ios_client *client,
                                                    uint64_t app_id, aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        copy_buffer(client->value.acquire_free(app_id), output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_ios_client_download_ipa(aauth_appstore_ios_client *client, uint64_t app_id,
                                                const char *path, int include_sinf,
                                                aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output && (include_sinf == 0 || include_sinf == 1));
        const auto r = client->value.download(app_id, utf8_path(path), include_sinf != 0);
        write_json({{"offer",
                     {{"app_id", r.offer.app_id},
                      {"bundle", r.offer.bundle},
                      {"version", r.offer.version},
                      {"external_version_id", r.offer.external_version_id}}},
                    {"path", path_string(r.path)},
                    {"material_directory", path_string(r.material_directory)},
                    {"bytes", r.bytes},
                    {"members", r.members},
                    {"sha256", r.sha256},
                    {"main_cryptids", r.main_cryptids},
                    {"version_ids", r.version_ids}},
                   output);
#else
        (void)client;
        (void)app_id;
        (void)path;
        (void)include_sinf;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_mac_client_create(const aauth_store_session *session,
                                              const char *directory, const char *country,
                                              const aauth_client_options *options,
                                              const aauth_device_headers *headers,
                                              const char *headers_json,
                                              aauth_appstore_mac_client **output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(session && country && output);
        auto result = std::make_unique<aauth_appstore_mac_client>(aauth_appstore_mac_client{
            AppStoreMacClient(session->value, utf8_path(directory), country,
                              store_options(options, headers, headers_json))});
        *output = result.release();
#else
        (void)session;
        (void)directory;
        (void)country;
        (void)options;
        (void)headers;
        (void)headers_json;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_mac_client_catalog(aauth_appstore_mac_client *client, uint64_t app_id,
                                               aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        copy_buffer(client->value.catalog(app_id), output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_mac_client_metadata(aauth_appstore_mac_client *client, uint64_t app_id,
                                                aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        copy_buffer(client->value.metadata(app_id), output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_mac_client_download(aauth_appstore_mac_client *client, uint64_t app_id,
                                                const char *path, int package,
                                                aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output && (package == 0 || package == 1));
        const auto r = package ? client->value.download_package(app_id, utf8_path(path))
                               : client->value.download(app_id, utf8_path(path));
        write_json({{"offer",
                     {{"app_id", r.offer.app_id},
                      {"bundle", r.offer.bundle},
                      {"external_version_id", r.offer.external_version_id}}},
                    {"path", path_string(r.path)},
                    {"material_directory", path_string(r.material_directory)},
                    {"original_path", path_string(r.original_path)},
                    {"bytes", r.bytes},
                    {"version", r.version},
                    {"sha256", r.sha256},
                    {"version_ids", r.version_ids},
                    {"transport_wrapped", r.transport_wrapped},
                    {"package_validated", r.package_validated},
                    {"members", r.members}},
                   output);
#else
        (void)client;
        (void)app_id;
        (void)path;
        (void)package;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_generate_kbsync(uint64_t dsid, const uint8_t *hardware, size_t hardware_size,
                                   const uint8_t *entropy, size_t entropy_size,
                                   aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(hardware && (hardware_size == 6 || hardware_size == 20) &&
                (!entropy_size || entropy) && output);
        copy_buffer(generate_kbsync(dsid, {hardware, hardware_size}, {entropy, entropy_size}),
                    output);
#else
        (void)dsid;
        (void)hardware;
        (void)hardware_size;
        (void)entropy;
        (void)entropy_size;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_unwrap_testflight_transport(const char *source, const char *destination,
                                               const uint8_t *hardware, size_t hardware_size,
                                               const uint8_t *dp_info, size_t dp_info_size,
                                               aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(hardware && hardware_size == 20 && dp_info && dp_info_size == 88 && output);
        const auto bytes =
            unwrap_testflight_transport(utf8_path(source), utf8_path(destination),
                                        {hardware, hardware_size}, {dp_info, dp_info_size});
        write_json({{"bytes", bytes}}, output);
#else
        (void)source;
        (void)destination;
        (void)hardware;
        (void)hardware_size;
        (void)dp_info;
        (void)dp_info_size;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_normalize_testflight_ipa(const char *source, const char *destination,
                                            const char *bundle, aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(output);
        write_json(archive_info(normalize_testflight_ipa(utf8_path(source), utf8_path(destination),
                                                         bundle ? bundle : "")),
                   output);
#else
        (void)source;
        (void)destination;
        (void)bundle;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_unwrap_appstore_mac_package(const char *source, const char *destination,
                                               const uint8_t *hardware, size_t hardware_size,
                                               const uint8_t *dp_info, size_t dp_info_size,
                                               aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(hardware && hardware_size == 6 && dp_info && dp_info_size == 88 && output);
        const auto r =
            unwrap_appstore_mac_package(utf8_path(source), utf8_path(destination),
                                        {hardware, hardware_size}, {dp_info, dp_info_size});
        write_json({{"bytes", r.bytes}, {"members", r.members}, {"sha256", r.sha256}}, output);
#else
        (void)source;
        (void)destination;
        (void)hardware;
        (void)hardware_size;
        (void)dp_info;
        (void)dp_info_size;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

void aauth_testflight_client_free(aauth_testflight_client *client) { delete client; }

aauth_status aauth_appstore_ios_client_offer(aauth_appstore_ios_client *client, uint64_t app_id,
                                             aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        const auto offer = client->value.offer(app_id);
        write_json({{"app_id", offer.app_id},
                    {"bundle", offer.bundle},
                    {"version", offer.version},
                    {"external_version_id", offer.external_version_id}},
                   output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

aauth_status aauth_appstore_mac_client_offer(aauth_appstore_mac_client *client, uint64_t app_id,
                                             aauth_client_buffer *output) {
    return guard([&] {
#ifdef APPLE_AUTH_WITH_TESTFLIGHT
        require(client && app_id && output);
        const auto offer = client->value.offer(app_id);
        write_json({{"app_id", offer.app_id},
                    {"bundle", offer.bundle},
                    {"external_version_id", offer.external_version_id}},
                   output);
#else
        (void)client;
        (void)app_id;
        (void)output;
        throw apple_auth::Error(ErrorCode::unsupported,
                                "Rebuild with APPLE_AUTH_WITH_TESTFLIGHT=ON");
#endif
    });
}

void aauth_appstore_ios_client_free(aauth_appstore_ios_client *client) { delete client; }

void aauth_appstore_mac_client_free(aauth_appstore_mac_client *client) { delete client; }

} // extern "C"
