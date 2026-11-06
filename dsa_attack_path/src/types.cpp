#include "strix_dsa/types.hpp"

#include <algorithm>
#include <cctype>

namespace strix_dsa {
namespace {

std::string lower_copy(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

}  // namespace

std::string relation_type_to_string(RelationType relation) {
    switch (relation) {
        case RelationType::InternetExposed:
            return "InternetExposed";
        case RelationType::CrossZoneAdmin:
            return "CrossZoneAdmin";
        case RelationType::SameZoneData:
            return "SameZoneData";
        case RelationType::LoggedJumpHost:
            return "LoggedJumpHost";
        case RelationType::Unclassified:
            return "Unclassified";
    }
    return "Unclassified";
}

std::string edge_status_to_string(EdgeStatus status) {
    switch (status) {
        case EdgeStatus::Active:
            return "Active";
        case EdgeStatus::Disabled:
            return "Disabled";
        case EdgeStatus::JumpHostForced:
            return "JumpHostForced";
    }
    return "Active";
}

bool parse_relation_type(const std::string& text, RelationType& out) {
    const std::string value = lower_copy(text);
    if (value == "internetexposed" || value == "internet") {
        out = RelationType::InternetExposed;
        return true;
    }
    if (value == "crosszoneadmin" || value == "admin") {
        out = RelationType::CrossZoneAdmin;
        return true;
    }
    if (value == "samezonedata" || value == "data") {
        out = RelationType::SameZoneData;
        return true;
    }
    if (value == "loggedjumphost" || value == "jump") {
        out = RelationType::LoggedJumpHost;
        return true;
    }
    if (value == "unclassified" || value == "default") {
        out = RelationType::Unclassified;
        return true;
    }
    return false;
}

bool parse_edge_status(const std::string& text, EdgeStatus& out) {
    const std::string value = lower_copy(text);
    if (value == "active") {
        out = EdgeStatus::Active;
        return true;
    }
    if (value == "disabled") {
        out = EdgeStatus::Disabled;
        return true;
    }
    if (value == "jumphostforced" || value == "jump") {
        out = EdgeStatus::JumpHostForced;
        return true;
    }
    return false;
}

}  // namespace strix_dsa
