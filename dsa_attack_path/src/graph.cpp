#include "strix_dsa/graph.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <queue>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace strix_dsa {
namespace {

struct ViewEdge {
    int from = 0;
    int to = 0;
    int to_index = 0;
    std::string protocol;
    RelationType relation = RelationType::Unclassified;
    bool inferred = false;
    double probability = 0.0;
    EdgeStatus status = EdgeStatus::Active;

    bool traversable() const { return status != EdgeStatus::Disabled && probability > 0.0; }
};

long long edge_key(int from, int to) {
    return (static_cast<long long>(static_cast<unsigned int>(from)) << 32) |
           static_cast<unsigned int>(to);
}

void trim(std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos) {
        value.clear();
        return;
    }
    value = value.substr(first, value.find_last_not_of(" \t\r") - first + 1);
}

bool parse_double_token(const std::string& text, double& out) {
    if (text.empty()) return false;
    try {
        std::size_t used = 0;
        out = std::stod(text, &used);
        return used == text.size() && std::isfinite(out);
    } catch (const std::exception&) {
        return false;
    }
}

bool parse_bool_token(const std::string& text, bool& out) {
    std::string value = text;
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (value == "true" || value == "1" || value == "yes") {
        out = true;
        return true;
    }
    if (value == "false" || value == "0" || value == "no") {
        out = false;
        return true;
    }
    return false;
}

bool is_data_node(const Node& node) {
    return node.type() == "Database" || node.type() == "Data Service";
}

bool is_application_node(const Node& node) { return node.type() == "Application Server"; }

bool is_identity_node(const Node& node) { return node.type() == "Identity Service"; }

bool is_admin_zone(const Node& node) {
    return node.zone() == "Management" || node.zone() == "Security";
}

RelationType infer_relation(const Node& from, const Node& to) {
    const bool same_zone = from.zone() == to.zone();
    if (from.is_entry_point() && from.zone() == "DMZ" && to.zone() == "DMZ" &&
        to.type() == "Gateway") {
        return RelationType::InternetExposed;
    }
    if (!same_zone && (is_identity_node(from) || is_identity_node(to) || is_admin_zone(from) ||
                       is_admin_zone(to) || to.zone() == "CrownJewel" || to.is_crown_jewel())) {
        return RelationType::CrossZoneAdmin;
    }
    if (same_zone && ((is_application_node(from) && is_data_node(to)) ||
                      (is_data_node(from) && is_data_node(to)))) {
        return RelationType::SameZoneData;
    }
    return RelationType::Unclassified;
}

double table_probability(RelationType relation, const ProbabilityTable& table) {
    switch (relation) {
        case RelationType::InternetExposed:
            return table.p_internet;
        case RelationType::CrossZoneAdmin:
            return table.p_admin;
        case RelationType::SameZoneData:
            return table.p_data;
        case RelationType::LoggedJumpHost:
            return table.p_jump;
        case RelationType::Unclassified:
            return table.p_default;
    }
    return table.p_default;
}

std::vector<std::string> compress_zones(const std::vector<std::string>& zones) {
    std::vector<std::string> out;
    for (const auto& zone : zones) {
        if (out.empty() || out.back() != zone) out.push_back(zone);
    }
    return out;
}

int index_of(const std::vector<Node>& nodes, int id) {
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].id() == id) return static_cast<int>(i);
    }
    return -1;
}

PathEdge make_path_edge(const std::vector<Node>& nodes, const ViewEdge& edge) {
    PathEdge out;
    out.from = edge.from;
    out.to = edge.to;
    out.protocol = edge.protocol;
    out.relation_type = relation_type_to_string(edge.relation);
    out.probability = edge.probability;
    out.status = edge_status_to_string(edge.status);
    out.inferred = edge.inferred;
    const int from_index = index_of(nodes, edge.from);
    if (from_index >= 0) {
        out.from_name = nodes[from_index].name();
        out.from_zone = nodes[from_index].zone();
    }
    out.to_name = nodes[edge.to_index].name();
    out.to_zone = nodes[edge.to_index].zone();
    return out;
}

std::vector<std::vector<ViewEdge>> build_view(const std::vector<Node>& nodes,
                                              const std::vector<Edge>& edges,
                                              const Scenario& scenario) {
    std::unordered_set<long long> disabled;
    std::unordered_set<long long> jumps;
    for (const auto& item : scenario.disabled_edges) disabled.insert(edge_key(item.first, item.second));
    for (const auto& item : scenario.jump_host_edges) jumps.insert(edge_key(item.first, item.second));

    std::vector<std::vector<ViewEdge>> adj(nodes.size());
    for (const auto& edge : edges) {
        const int from_index = index_of(nodes, edge.from());
        const int to_index = index_of(nodes, edge.to());
        if (from_index < 0 || to_index < 0) continue;
        ViewEdge view;
        view.from = edge.from();
        view.to = edge.to();
        view.to_index = to_index;
        view.protocol = edge.protocol();
        view.relation = edge.relation();
        view.inferred = edge.relation_inferred();
        view.status = edge.baseline_status();
        const long long key = edge_key(edge.from(), edge.to());
        if (disabled.count(key)) {
            view.status = EdgeStatus::Disabled;
        } else if (jumps.count(key) && view.status != EdgeStatus::Disabled) {
            view.status = EdgeStatus::JumpHostForced;
        }
        if (view.status == EdgeStatus::JumpHostForced) {
            view.probability = scenario.table.p_jump;
        } else if (edge.has_probability_override()) {
            view.probability = edge.probability_override();
        } else {
            view.probability = table_probability(edge.relation(), scenario.table);
        }
        adj[from_index].push_back(view);
    }
    return adj;
}

struct BfsResult {
    std::vector<int> dist;
    std::vector<int> parent;
    std::vector<int> parent_edge;
};

BfsResult run_bfs(const std::vector<std::vector<ViewEdge>>& adj, int start_index) {
    const int n = static_cast<int>(adj.size());
    BfsResult result;
    result.dist.assign(n, -1);
    result.parent.assign(n, -1);
    result.parent_edge.assign(n, -1);
    std::queue<int> queue;
    result.dist[start_index] = 0;
    queue.push(start_index);
    while (!queue.empty()) {
        const int current = queue.front();
        queue.pop();
        for (std::size_t i = 0; i < adj[current].size(); ++i) {
            const ViewEdge& edge = adj[current][i];
            if (!edge.traversable() || result.dist[edge.to_index] != -1) continue;
            result.dist[edge.to_index] = result.dist[current] + 1;
            result.parent[edge.to_index] = current;
            result.parent_edge[edge.to_index] = static_cast<int>(i);
            queue.push(edge.to_index);
        }
    }
    return result;
}

std::vector<int> reconstruct_nodes(const std::vector<Node>& nodes, const std::vector<int>& parent,
                                   int start_index, int target_index) {
    std::vector<int> path;
    for (int at = target_index; at != -1; at = parent[at]) path.push_back(nodes[at].id());
    std::reverse(path.begin(), path.end());
    if (path.empty() || path.front() != nodes[start_index].id()) return {};
    return path;
}

std::vector<PathEdge> reconstruct_edges(const std::vector<Node>& nodes,
                                        const std::vector<std::vector<ViewEdge>>& adj,
                                        const std::vector<int>& parent,
                                        const std::vector<int>& parent_edge, int target_index) {
    std::vector<PathEdge> edges;
    for (int at = target_index; parent[at] != -1; at = parent[at]) {
        const ViewEdge& edge = adj[parent[at]][parent_edge[at]];
        edges.push_back(make_path_edge(nodes, edge));
    }
    std::reverse(edges.begin(), edges.end());
    return edges;
}

struct DijkstraResult {
    bool found = false;
    double distance = 0.0;
    int hops = 0;
    std::vector<int> parent;
    std::vector<int> parent_edge;
};

DijkstraResult run_dijkstra(const std::vector<std::vector<ViewEdge>>& adj, int start_index,
                            int target_index) {
    const int n = static_cast<int>(adj.size());
    const double inf = std::numeric_limits<double>::infinity();
    std::vector<double> dist(n, inf);
    std::vector<int> hops(n, std::numeric_limits<int>::max());
    DijkstraResult result;
    result.parent.assign(n, -1);
    result.parent_edge.assign(n, -1);
    dist[start_index] = 0.0;
    hops[start_index] = 0;
    using Item = std::tuple<double, int, int>;
    std::priority_queue<Item, std::vector<Item>, std::greater<Item>> queue;
    queue.emplace(0.0, 0, start_index);
    std::vector<bool> settled(n, false);
    while (!queue.empty()) {
        const auto [current_dist, current_hops, current] = queue.top();
        queue.pop();
        if (settled[current]) continue;
        if (current_dist > dist[current] + 1e-12) continue;
        settled[current] = true;
        if (current == target_index) break;
        for (std::size_t i = 0; i < adj[current].size(); ++i) {
            const ViewEdge& edge = adj[current][i];
            if (!edge.traversable() || settled[edge.to_index]) continue;
            const double weight = edge.probability >= 1.0 ? 0.0 : -std::log(edge.probability);
            const double next_dist = dist[current] + weight;
            const int next_hops = hops[current] + 1;
            const bool better_distance = next_dist + 1e-12 < dist[edge.to_index];
            const bool same_distance_fewer_hops =
                std::fabs(next_dist - dist[edge.to_index]) <= 1e-12 && next_hops < hops[edge.to_index];
            if (better_distance || same_distance_fewer_hops) {
                dist[edge.to_index] = next_dist;
                hops[edge.to_index] = next_hops;
                result.parent[edge.to_index] = current;
                result.parent_edge[edge.to_index] = static_cast<int>(i);
                queue.emplace(next_dist, next_hops, edge.to_index);
            }
        }
    }
    result.found = settled[target_index];
    result.distance = dist[target_index];
    result.hops = hops[target_index];
    return result;
}

struct DfsResult {
    std::vector<std::vector<int>> paths;
    std::unordered_map<long long, std::size_t> frequency;
    bool truncated = false;
};

void dfs_visit(const std::vector<Node>& nodes, const std::vector<std::vector<ViewEdge>>& adj,
               int current, int target, std::size_t depth, std::size_t max_depth,
               std::size_t max_paths, std::vector<bool>& visited, std::vector<int>& path,
               DfsResult& out) {
    if (out.truncated) return;
    visited[current] = true;
    path.push_back(nodes[current].id());
    if (current == target) {
        if (out.paths.size() >= max_paths) {
            out.truncated = true;
        } else {
            out.paths.push_back(path);
            for (std::size_t i = 0; i + 1 < path.size(); ++i) {
                out.frequency[edge_key(path[i], path[i + 1])]++;
            }
        }
    } else if (depth < max_depth) {
        for (const auto& edge : adj[current]) {
            if (out.truncated) break;
            if (!edge.traversable() || visited[edge.to_index]) continue;
            dfs_visit(nodes, adj, edge.to_index, target, depth + 1, max_depth, max_paths, visited,
                      path, out);
        }
    } else {
        for (const auto& edge : adj[current]) {
            if (edge.traversable() && !visited[edge.to_index]) {
                out.truncated = true;
                break;
            }
        }
    }
    path.pop_back();
    visited[current] = false;
}

DfsResult run_dfs(const std::vector<Node>& nodes, const std::vector<std::vector<ViewEdge>>& adj,
                  int start_index, int target_index, const SearchOptions& options) {
    DfsResult result;
    if (options.max_depth == 0 || options.max_paths == 0) {
        result.truncated = true;
        return result;
    }
    std::vector<bool> visited(nodes.size(), false);
    std::vector<int> path;
    dfs_visit(nodes, adj, start_index, target_index, 0, options.max_depth, options.max_paths,
              visited, path, result);
    return result;
}

std::vector<std::string> zones_for(const std::vector<Node>& nodes, const std::vector<int>& ids) {
    std::vector<std::string> zones;
    for (int id : ids) {
        const int index = index_of(nodes, id);
        zones.push_back(index >= 0 ? nodes[index].zone() : "");
    }
    return compress_zones(zones);
}

}  // namespace

bool Graph::add_node(const Node& node) {
    if (node.id() <= 0 || node.impact() < 0 || node.impact() > 100) {
        std::cerr << "[!] Invalid node: ID must be positive and Impact must be in [0, 100].\n";
        return false;
    }
    for (const auto& existing : nodes_) {
        if (existing.id() == node.id()) {
            std::cerr << "[!] Node ID " << node.id() << " already exists.\n";
            return false;
        }
    }
    nodes_.push_back(node);
    return true;
}

bool Graph::add_edge(const Edge& edge) {
    if (!node_exists(edge.from()) || !node_exists(edge.to())) {
        std::cerr << "[!] Edge endpoint does not exist: " << edge.from() << " -> " << edge.to()
                  << "\n";
        return false;
    }
    if (edge.has_probability_override()) {
        const double p = edge.probability_override();
        if (!std::isfinite(p) || p < 0.0 || p > 1.0) {
            std::cerr << "[!] Edge probability must be in [0, 1].\n";
            return false;
        }
    }
    for (const auto& existing : edges_) {
        if (existing.from() == edge.from() && existing.to() == edge.to()) {
            std::cerr << "[!] Duplicate edge " << edge.from() << " -> " << edge.to() << ".\n";
            return false;
        }
    }
    edges_.push_back(edge);
    return true;
}

bool Graph::node_exists(int id) const { return get_node(id) != nullptr; }

const Node* Graph::get_node(int id) const {
    for (const auto& node : nodes_) {
        if (node.id() == id) return &node;
    }
    return nullptr;
}

const std::vector<Node>& Graph::nodes() const { return nodes_; }
const std::vector<Edge>& Graph::edges() const { return edges_; }

bool Graph::load_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[!] Cannot open topology file: " << filename << "\n";
        return false;
    }
    nodes_.clear();
    edges_.clear();
    try {
        std::string line;
        std::string section;
        while (std::getline(file, line)) {
            trim(line);
            if (line.empty() || line[0] == '#') continue;
            if (line == "[NODES]") {
                section = "NODES";
                continue;
            }
            if (line == "[EDGES]") {
                section = "EDGES";
                continue;
            }
            std::stringstream stream(line);
            std::string field;
            std::vector<std::string> tokens;
            while (std::getline(stream, field, ',')) {
                trim(field);
                tokens.push_back(field);
            }
            if (section == "NODES" && tokens.size() >= 4) {
                const int id = std::stoi(tokens[0]);
                const int impact = std::stoi(tokens[3]);
                const std::string zone = tokens.size() >= 5 ? tokens[4] : "Internal";
                bool is_entry = false;
                bool is_crown = false;
                if (tokens.size() >= 6 && !parse_bool_token(tokens[5], is_entry)) {
                    throw std::runtime_error("invalid entry flag");
                }
                if (tokens.size() >= 7 && !parse_bool_token(tokens[6], is_crown)) {
                    throw std::runtime_error("invalid crown jewel flag");
                }
                if (!add_node(Node(id, tokens[1], tokens[2], zone, impact, is_entry, is_crown))) {
                    throw std::runtime_error("invalid or duplicate node");
                }
            } else if (section == "EDGES" && tokens.size() >= 3) {
                const int from = std::stoi(tokens[0]);
                const int to = std::stoi(tokens[1]);
                const std::string protocol = tokens[2];
                RelationType relation = RelationType::Unclassified;
                bool inferred = true;
                double override_probability = -1.0;
                EdgeStatus status = EdgeStatus::Active;
                bool explicit_relation = false;

                if (tokens.size() >= 4) {
                    if (!parse_relation_type(tokens[3], relation)) {
                        throw std::runtime_error("invalid relation type");
                    }
                    explicit_relation = true;
                    inferred = false;
                }
                if (tokens.size() >= 5) {
                    double parsed = 0.0;
                    if (!parse_double_token(tokens[4], parsed) || parsed < 0.0 || parsed > 1.0) {
                        throw std::runtime_error("edge probability out of range");
                    }
                    override_probability = parsed;
                }
                if (tokens.size() >= 6 && !parse_edge_status(tokens[5], status)) {
                    throw std::runtime_error("invalid edge status");
                }
                if (!explicit_relation) {
                    const Node* source = get_node(from);
                    const Node* target = get_node(to);
                    if (!source || !target) throw std::runtime_error("edge endpoint missing");
                    relation = infer_relation(*source, *target);
                    inferred = true;
                }
                if (!add_edge(Edge(from, to, protocol, relation, override_probability, inferred,
                                   status))) {
                    throw std::runtime_error("invalid edge");
                }
            } else {
                throw std::runtime_error("malformed record or record outside [NODES]/[EDGES]");
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "[!] Invalid topology data in " << filename << ": " << error.what() << "\n";
        nodes_.clear();
        edges_.clear();
        return false;
    }
    std::cerr << "[+] Loaded SIMULATED network topology: " << nodes_.size() << " nodes, "
              << edges_.size() << " edges.\n";
    return true;
}

AnalysisResult Graph::analyze(int start_id, int target_id, const SearchOptions& options,
                              const Scenario& scenario) const {
    AnalysisResult bundle;
    const int start_index = index_of(nodes_, start_id);
    const int target_index = index_of(nodes_, target_id);
    if (start_index < 0 || target_index < 0) return bundle;

    const auto adj = build_view(nodes_, edges_, scenario);
    const BfsResult bfs = run_bfs(adj, start_index);
    const DfsResult dfs = run_dfs(nodes_, adj, start_index, target_index, options);

    bundle.dfs.total_paths_found = dfs.paths.size();
    bundle.dfs.max_depth = options.max_depth;
    bundle.dfs.max_paths = options.max_paths;
    bundle.dfs.truncated = dfs.truncated;
    bundle.dfs.frequency_complete = !dfs.truncated;
    bundle.dfs.all_paths = dfs.paths;

    bundle.reachability.reachable = bfs.dist[target_index] >= 0;
    bundle.reachability.total_paths = dfs.paths.size();
    bundle.reachability.truncated = dfs.truncated;
    if (bundle.reachability.reachable) {
        bundle.reachability.shortest_hops = bfs.dist[target_index];
        bundle.reachability.nodes = reconstruct_nodes(nodes_, bfs.parent, start_index, target_index);
        bundle.reachability.edges =
            reconstruct_edges(nodes_, adj, bfs.parent, bfs.parent_edge, target_index);
        bundle.reachability.zone_chain = zones_for(nodes_, bundle.reachability.nodes);
    }

    const Node* target_node = &nodes_[target_index];
    bundle.representative.target_impact = target_node->impact();
    if (start_index == target_index) {
        bundle.representative.found = true;
        bundle.representative.nodes = {start_id};
        bundle.representative.has_probability = true;
        bundle.representative.path_probability = 1.0;
        bundle.representative.zone_sequence = {target_node->zone()};
    } else {
        const DijkstraResult dijkstra = run_dijkstra(adj, start_index, target_index);
        bundle.representative.found = dijkstra.found;
        if (dijkstra.found) {
            bundle.representative.nodes =
                reconstruct_nodes(nodes_, dijkstra.parent, start_index, target_index);
            bundle.representative.edges =
                reconstruct_edges(nodes_, adj, dijkstra.parent, dijkstra.parent_edge, target_index);
            bundle.representative.has_probability = true;
            bundle.representative.path_probability = 1.0;
            for (const auto& edge : bundle.representative.edges) {
                bundle.representative.path_probability *= edge.probability;
                if (!bundle.representative.has_weakest ||
                    edge.probability < bundle.representative.weakest.probability) {
                    bundle.representative.weakest = edge;
                    bundle.representative.has_weakest = true;
                }
            }
            bundle.representative.zone_sequence = zones_for(nodes_, bundle.representative.nodes);
        }
    }

    std::vector<int> jewel_indexes;
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].is_crown_jewel()) jewel_indexes.push_back(static_cast<int>(i));
    }
    std::vector<std::vector<char>> reaches_jewel(jewel_indexes.size(),
                                                 std::vector<char>(nodes_.size(), 0));
    std::vector<std::vector<int>> reverse(nodes_.size());
    for (std::size_t from = 0; from < adj.size(); ++from) {
        for (const auto& edge : adj[from]) {
            if (edge.traversable()) reverse[edge.to_index].push_back(static_cast<int>(from));
        }
    }
    for (std::size_t j = 0; j < jewel_indexes.size(); ++j) {
        std::queue<int> queue;
        reaches_jewel[j][jewel_indexes[j]] = 1;
        queue.push(jewel_indexes[j]);
        while (!queue.empty()) {
            const int current = queue.front();
            queue.pop();
            for (int previous : reverse[current]) {
                if (reaches_jewel[j][previous]) continue;
                reaches_jewel[j][previous] = 1;
                queue.push(previous);
            }
        }
        CrownJewelStatus status;
        status.id = nodes_[jewel_indexes[j]].id();
        status.name = nodes_[jewel_indexes[j]].name();
        status.impact = nodes_[jewel_indexes[j]].impact();
        status.reachable = bfs.dist[jewel_indexes[j]] >= 0;
        status.shortest_hops = status.reachable ? bfs.dist[jewel_indexes[j]] : -1;
        bundle.crown_jewels.push_back(status);
    }

    std::unordered_map<long long, std::pair<int, int>> jewel_stats;
    for (std::size_t from = 0; from < adj.size(); ++from) {
        if (bfs.dist[from] < 0) continue;
        for (const auto& edge : adj[from]) {
            if (!edge.traversable()) continue;
            int count = 0;
            int impact = 0;
            for (std::size_t j = 0; j < jewel_indexes.size(); ++j) {
                if (!reaches_jewel[j][edge.to_index]) continue;
                ++count;
                impact += nodes_[jewel_indexes[j]].impact();
            }
            jewel_stats[edge_key(edge.from, edge.to)] = {count, impact};
        }
    }

    for (std::size_t from = 0; from < adj.size(); ++from) {
        for (const auto& edge : adj[from]) {
            bundle.topology_edges.push_back(make_path_edge(nodes_, edge));
        }
    }

    for (std::size_t from = 0; from < adj.size(); ++from) {
        for (const auto& edge : adj[from]) {
            const long long key = edge_key(edge.from, edge.to);
            const std::size_t count = dfs.frequency.count(key) ? dfs.frequency.at(key) : 0;
            if (count == 0) continue;
            BottleneckEdge item;
            item.edge = make_path_edge(nodes_, edge);
            item.path_count = count;
            item.path_share_percent =
                dfs.paths.empty()
                    ? 0.0
                    : (100.0 * static_cast<double>(count) / static_cast<double>(dfs.paths.size()));
            if (jewel_stats.count(key)) {
                item.crown_jewels_count = jewel_stats[key].first;
                item.total_impact = jewel_stats[key].second;
            }
            item.frequency_complete = !dfs.truncated;
            bundle.bottlenecks.push_back(item);
        }
    }
    std::sort(bundle.bottlenecks.begin(), bundle.bottlenecks.end(),
              [](const BottleneckEdge& a, const BottleneckEdge& b) {
                  if (a.crown_jewels_count != b.crown_jewels_count) {
                      return a.crown_jewels_count > b.crown_jewels_count;
                  }
                  if (a.total_impact != b.total_impact) return a.total_impact > b.total_impact;
                  if (a.path_count != b.path_count) return a.path_count > b.path_count;
                  if (a.edge.probability != b.edge.probability) {
                      return a.edge.probability > b.edge.probability;
                  }
                  if (a.edge.from != b.edge.from) return a.edge.from < b.edge.from;
                  return a.edge.to < b.edge.to;
              });
    return bundle;
}

}  // namespace strix_dsa
