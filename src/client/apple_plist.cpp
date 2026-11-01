#include "client/client_internal.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <cmath>
#include <limits>

namespace apple_auth::netdetail {
namespace {
struct Owned {
    CFTypeRef value;
    explicit Owned(CFTypeRef input) : value(input) { require(value, "Cannot allocate plist value"); }
    ~Owned() { if (value) CFRelease(value); }
    Owned(const Owned&) = delete;
    CFTypeRef release() { const auto result = value; value = nullptr; return result; }
};

std::string string_value(CFStringRef value) {
    const auto size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), kCFStringEncodingUTF8);
    require(size >= 0 && size <= 16 * 1024 * 1024, "Invalid plist string length");
    std::string result(static_cast<std::size_t>(size) + 1, '\0');
    CFIndex written = 0;
    const auto converted = CFStringGetBytes(value, CFRangeMake(0, CFStringGetLength(value)),
                                            kCFStringEncodingUTF8, 0, false,
                                            reinterpret_cast<UInt8*>(result.data()), size, &written);
    require(converted == CFStringGetLength(value), "Invalid UTF-8 plist string");
    result.resize(static_cast<std::size_t>(written));
    return result;
}

CFStringRef make_string(const std::string& value) {
    return CFStringCreateWithBytes(kCFAllocatorDefault,
                                   reinterpret_cast<const UInt8*>(value.data()),
                                   static_cast<CFIndex>(value.size()), kCFStringEncodingUTF8, false);
}

Json decode(CFTypeRef value, unsigned depth) {
    require(value && depth < 64, "Invalid plist nesting");
    const auto type = CFGetTypeID(value);
    if (type == CFDictionaryGetTypeID()) {
        const auto dictionary = static_cast<CFDictionaryRef>(value);
        const auto count = CFDictionaryGetCount(dictionary);
        std::vector<const void*> keys(static_cast<std::size_t>(count)), values(keys.size());
        CFDictionaryGetKeysAndValues(dictionary, keys.data(), values.data());
        Json result = Json::object();
        for (std::size_t index = 0; index < keys.size(); ++index) {
            require(CFGetTypeID(keys[index]) == CFStringGetTypeID(), "Invalid plist dictionary key");
            result[string_value(static_cast<CFStringRef>(keys[index]))] = decode(values[index], depth + 1);
        }
        return result;
    }
    if (type == CFArrayGetTypeID()) {
        const auto array = static_cast<CFArrayRef>(value);
        Json result = Json::array();
        for (CFIndex index = 0; index < CFArrayGetCount(array); ++index)
            result.push_back(decode(CFArrayGetValueAtIndex(array, index), depth + 1));
        return result;
    }
    if (type == CFStringGetTypeID()) return string_value(static_cast<CFStringRef>(value));
    if (type == CFDataGetTypeID()) {
        const auto data = static_cast<CFDataRef>(value);
        const auto count = CFDataGetLength(data);
        return Json::binary(count ? Bytes(CFDataGetBytePtr(data), CFDataGetBytePtr(data) + count) : Bytes{});
    }
    if (type == CFBooleanGetTypeID()) return CFBooleanGetValue(static_cast<CFBooleanRef>(value));
    if (type == CFNumberGetTypeID()) {
        const auto number = static_cast<CFNumberRef>(value);
        if (CFNumberIsFloatType(number)) {
            double result = 0;
            require(CFNumberGetValue(number, kCFNumberDoubleType, &result), "Invalid plist number");
            return result;
        }
        std::int64_t result = 0;
        require(CFNumberGetValue(number, kCFNumberSInt64Type, &result), "Invalid plist integer");
        return result;
    }
    if (type == CFDateGetTypeID()) {
        const auto value_seconds = CFDateGetAbsoluteTime(static_cast<CFDateRef>(value));
        const auto seconds = std::floor(value_seconds);
        return Json{{"seconds", static_cast<std::int64_t>(seconds)},
                    {"microseconds", static_cast<std::int64_t>((value_seconds - seconds) * 1000000)}};
    }
    throw Error("Unsupported plist value");
}

CFTypeRef encode(const Json& value, unsigned depth) {
    require(depth < 64, "Invalid plist nesting");
    if (value.is_object()) {
        auto dictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                     &kCFTypeDictionaryKeyCallBacks,
                                                     &kCFTypeDictionaryValueCallBacks);
        Owned result(dictionary);
        for (const auto& [key, child] : value.items()) {
            Owned name(make_string(key)), node(encode(child, depth + 1));
            CFDictionarySetValue(dictionary, name.value, node.value);
        }
        return result.release();
    }
    if (value.is_array()) {
        auto array = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        Owned result(array);
        for (const auto& child : value) {
            Owned node(encode(child, depth + 1));
            CFArrayAppendValue(array, node.value);
        }
        return result.release();
    }
    if (value.is_binary()) {
        const auto& data = value.get_binary();
        return CFDataCreate(kCFAllocatorDefault, data.data(), static_cast<CFIndex>(data.size()));
    }
    if (value.is_string()) return make_string(value.get_ref<const std::string&>());
    if (value.is_boolean()) return CFRetain(value.get<bool>() ? kCFBooleanTrue : kCFBooleanFalse);
    if (value.is_number_integer()) {
        require(!value.is_number_unsigned() || value.get<std::uint64_t>() <= INT64_MAX,
                "Plist integer exceeds signed 64-bit range");
        const auto number = value.get<std::int64_t>();
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &number);
    }
    if (value.is_number_float()) {
        const auto number = value.get<double>();
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &number);
    }
    throw Error("Unsupported JSON value in plist");
}
} // namespace

Json parse_plist(View input) {
    require(!input.empty() && input.size() <= 16 * 1024 * 1024, "Invalid plist size");
    require(str(input).find("<!ENTITY") == std::string::npos, "Plist entities are unsupported");
    Owned data(CFDataCreate(kCFAllocatorDefault, input.data(), static_cast<CFIndex>(input.size())));
    CFErrorRef error = nullptr;
    const auto value = CFPropertyListCreateWithData(kCFAllocatorDefault,
                                                   static_cast<CFDataRef>(data.value),
                                                   kCFPropertyListImmutable, nullptr, &error);
    if (error) CFRelease(error);
    require(value, "Invalid plist");
    Owned root(value);
    return decode(root.value, 0);
}

Bytes encode_plist(const Json& value) {
    Owned root(encode(value, 0));
    CFErrorRef error = nullptr;
    const auto encoded = CFPropertyListCreateData(kCFAllocatorDefault, root.value,
                                                 kCFPropertyListXMLFormat_v1_0, 0, &error);
    if (error) CFRelease(error);
    require(encoded, "Cannot encode plist");
    Owned data(encoded);
    const auto length = CFDataGetLength(encoded);
    require(length <= 16 * 1024 * 1024, "Encoded plist exceeds size limit");
    return Bytes(CFDataGetBytePtr(encoded), CFDataGetBytePtr(encoded) + length);
}
} // namespace apple_auth::netdetail
