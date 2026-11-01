#include "client/state_storage.hpp"
#include "crypto/backend.hpp"
#include <algorithm>

namespace apple_auth::netdetail {
namespace {
constexpr std::array<const char*, 6> state_names = {
    "identity.json", "adi.pb", "account-session.plist", "store-account-session.plist",
    "store/identity.json", "store/adi.pb"};

bool valid_name(const std::string& name) {
    return !name.empty() && name != "." && name != ".." &&
           name.find_first_of("/\\:") == std::string::npos && name.find('\0') == std::string::npos;
}
} // namespace

struct StateStorage::Backend {
    std::optional<Path> directory;
    std::map<std::string, Bytes> records;
    ~Backend() {
        for (auto& [name, data] : records) {
            (void)name;
            crypto::wipe(data.data(), data.size());
        }
    }
};

StateStorage::StateStorage() : backend_(std::make_shared<Backend>()) {}
StateStorage::StateStorage(Path directory) : StateStorage() {
    require(!directory.empty(), "State directory must not be empty; use an in-memory Client");
    backend_->directory = std::move(directory);
}
StateStorage::StateStorage(View snapshot) : StateStorage() {
    require(!snapshot.empty() && snapshot.size() <= maximum_state_size, "Invalid client state size");
    const auto saved = Json::parse(snapshot);
    require(saved.is_object() && saved.value("kind", "") == "apple-auth-state" &&
                saved.value("version", 0) == 1 && saved.contains("files") && saved.at("files").is_object(),
            "Invalid client state format");
    const auto& files = saved.at("files");
    require(files.size() <= state_names.size() && files.contains("identity.json"),
            "Client state is missing its identity");
    std::size_t total = 0;
    for (const auto& [name, value] : files.items()) {
        require(std::find(state_names.begin(), state_names.end(), name) != state_names.end() && value.is_string(),
                "Unknown client state record");
        auto data = unbase64(value.get<std::string>());
        total += data.size();
        require(total <= maximum_state_size, "Client state exceeds size limit");
        backend_->records.emplace(name, std::move(data));
    }
    require(!files.contains("store/adi.pb") || files.contains("store/identity.json"),
            "Store state is missing its identity");
}
StateStorage::StateStorage(std::shared_ptr<Backend> backend, std::string prefix)
    : backend_(std::move(backend)), prefix_(std::move(prefix)) {}

StateStorage StateStorage::child(const std::string& name) const {
    require(valid_name(name), "Invalid child state name");
    return StateStorage(backend_, prefix_ + name + "/");
}
bool StateStorage::exists(const std::string& name) const {
    require(valid_name(name), "Invalid state record name");
    const auto key = prefix_ + name;
    return backend_->directory ? std::filesystem::exists(*backend_->directory / key)
                               : backend_->records.contains(key);
}
Bytes StateStorage::read(const std::string& name, std::size_t limit) const {
    require(valid_name(name), "Invalid state record name");
    const auto key = prefix_ + name;
    if (backend_->directory) return read_file(*backend_->directory / key, limit);
    const auto found = backend_->records.find(key);
    require(found != backend_->records.end(), "State record does not exist: " + name);
    require(found->second.size() <= limit, "State record exceeds size limit");
    return found->second;
}
void StateStorage::write(const std::string& name, View data) {
    require(valid_name(name) && data.size() <= maximum_state_size, "Invalid state record");
    const auto key = prefix_ + name;
    if (backend_->directory) {
        write_private(*backend_->directory / key, data);
    } else {
        Bytes copied(data.begin(), data.end());
        auto& old = backend_->records[key];
        crypto::wipe(old.data(), old.size());
        old = std::move(copied);
    }
}
void StateStorage::remove(const std::string& name) {
    require(valid_name(name), "Invalid state record name");
    const auto key = prefix_ + name;
    if (backend_->directory) {
        std::filesystem::remove(*backend_->directory / key);
    } else if (const auto found = backend_->records.find(key); found != backend_->records.end()) {
        crypto::wipe(found->second.data(), found->second.size());
        backend_->records.erase(found);
    }
}
std::vector<std::string> StateStorage::names() const {
    std::vector<std::string> result;
    if (backend_->directory) {
        const auto directory = *backend_->directory / prefix_;
        if (std::filesystem::is_directory(directory)) {
            for (const auto& entry : std::filesystem::directory_iterator(directory))
                if (entry.is_regular_file()) result.push_back(entry.path().filename().string());
        }
    } else {
        for (const auto& [key, data] : backend_->records) {
            (void)data;
            if (key.starts_with(prefix_) && key.find('/', prefix_.size()) == std::string::npos)
                result.push_back(key.substr(prefix_.size()));
        }
    }
    return result;
}
Bytes StateStorage::serialize() const {
    require(prefix_.empty(), "Serialize the root client state");
    Json files = Json::object();
    for (const auto* name : state_names) {
        const std::string key = name;
        const auto slash = key.find('/');
        const auto store = slash == std::string::npos ? *this : child(key.substr(0, slash));
        const auto record = slash == std::string::npos ? key : key.substr(slash + 1);
        if (store.exists(record)) files[key] = base64(store.read(record, maximum_state_size));
    }
    auto output = bytes(Json{{"kind", "apple-auth-state"}, {"version", 1}, {"files", files}}.dump());
    require(output.size() <= maximum_state_size, "Serialized client state exceeds size limit");
    return output;
}
} // namespace apple_auth::netdetail
