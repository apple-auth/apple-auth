#pragma once

#include "client/client_internal.hpp"

namespace apple_auth::netdetail {
inline constexpr std::size_t maximum_state_size = 16 * 1024 * 1024;

// The same named state records live either in RAM or in a private directory.
// Child stores share the backend, so Client snapshots include Store provisioning.
class StateStorage {
  public:
    StateStorage();
    explicit StateStorage(Path directory);
    explicit StateStorage(View snapshot);
    StateStorage child(const std::string& name) const;
    bool exists(const std::string& name) const;
    Bytes read(const std::string& name, std::size_t limit = 64 * 1024) const;
    void write(const std::string& name, View data);
    void remove(const std::string& name);
    std::vector<std::string> names() const;
    Bytes serialize() const;

  private:
    struct Backend;
    std::shared_ptr<Backend> backend_;
    std::string prefix_;
    StateStorage(std::shared_ptr<Backend> backend, std::string prefix);
};
} // namespace apple_auth::netdetail
