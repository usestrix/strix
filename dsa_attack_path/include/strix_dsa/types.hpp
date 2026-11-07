#ifndef STRIX_DSA_TYPES_HPP
#define STRIX_DSA_TYPES_HPP

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace strix_dsa {

// Edge probability is a simulation ranking weight, not a real-world exploit chance.
enum class RelationType {
    InternetExposed,
    CrossZoneAdmin,
    SameZoneData,
    LoggedJumpHost,
    Unclassified
};

enum class EdgeStatus { Active, Disabled, JumpHostForced };

struct ProbabilityTable {
    double p_internet = 0.80;
    double p_admin = 0.60;
    double p_data = 0.40;
    double p_jump = 0.20;
    double p_default = 0.40;
};

struct Scenario {
    std::vector<std::pair<int, int>> disabled_edges;
    std::vector<std::pair<int, int>> jump_host_edges;
    ProbabilityTable table;
};

struct SearchOptions {
    std::size_t max_depth = 12;
    std::size_t max_paths = 10000;
};

struct PathEdge {
    int from = 0;
    int to = 0;
    std::string from_name;
    std::string to_name;
    std::string from_zone;
    std::string to_zone;
    std::string protocol;
    std::string relation_type;
    double probability = 0.0;
    std::string status;
    bool inferred = false;
};

struct ReachabilityInfo {
    bool reachable = false;
    int shortest_hops = -1;
    std::vector<int> nodes;
    std::vector<PathEdge> edges;
    std::vector<std::string> zone_chain;
    std::size_t total_paths = 0;
    bool truncated = false;
};

struct RepresentativePath {
    bool found = false;
    std::vector<int> nodes;
    std::vector<PathEdge> edges;
    bool has_probability = false;
    double path_probability = 0.0;
    int target_impact = 0;
    bool has_weakest = false;
    PathEdge weakest;
    std::vector<std::string> zone_sequence;
};

struct BottleneckEdge {
    PathEdge edge;
    std::size_t path_count = 0;
    double path_share_percent = 0.0;
    int crown_jewels_count = 0;
    int total_impact = 0;
    bool frequency_complete = true;
};

struct DfsStatistics {
    std::size_t total_paths_found = 0;
    std::size_t max_depth = 0;
    std::size_t max_paths = 0;
    bool truncated = false;
    bool frequency_complete = true;
    std::vector<std::vector<int>> all_paths;
};

struct CrownJewelStatus {
    int id = 0;
    std::string name;
    int impact = 0;
    bool reachable = false;
    int shortest_hops = -1;
};

struct AnalysisResult {
    ReachabilityInfo reachability;
    RepresentativePath representative;
    std::vector<BottleneckEdge> bottlenecks;
    DfsStatistics dfs;
    std::vector<CrownJewelStatus> crown_jewels;
    std::vector<PathEdge> topology_edges;
};

std::string relation_type_to_string(RelationType relation);
std::string edge_status_to_string(EdgeStatus status);
bool parse_relation_type(const std::string& text, RelationType& out);
bool parse_edge_status(const std::string& text, EdgeStatus& out);

}  // namespace strix_dsa

#endif
