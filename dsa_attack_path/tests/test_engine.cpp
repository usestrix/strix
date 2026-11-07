#include "strix_dsa/graph.hpp"

#include <cmath>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

strix_dsa::Node make_node(int id, const std::string& type, const std::string& zone, int impact = 0,
                          bool entry = false, bool crown = false) {
    return strix_dsa::Node(id, "n" + std::to_string(id), type, zone, impact, entry, crown);
}

strix_dsa::Edge make_edge(int from, int to, double probability,
                          const std::string& protocol = "TCP/Generic") {
    return strix_dsa::Edge(from, to, protocol, strix_dsa::RelationType::Unclassified, probability,
                           false);
}

strix_dsa::SearchOptions search_all() {
    strix_dsa::SearchOptions options;
    options.max_depth = 20;
    options.max_paths = 100;
    return options;
}

void test_bfs_shortest() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Endpoint", "DMZ", 0, true, false)), "bfs node 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "bfs node 2");
    check(graph.add_node(make_node(3, "Server", "Internal")), "bfs node 3");
    check(graph.add_node(make_node(4, "Critical Asset", "CrownJewel", 90, false, true)),
          "bfs node 4");
    check(graph.add_edge(make_edge(1, 2, 0.5)), "bfs e12");
    check(graph.add_edge(make_edge(2, 4, 0.5)), "bfs e24");
    check(graph.add_edge(make_edge(1, 3, 0.5)), "bfs e13");
    check(graph.add_edge(make_edge(3, 2, 0.5)), "bfs e32");
    const auto result = graph.analyze(1, 4, search_all(), {});
    check(result.reachability.reachable, "bfs reachable");
    check(result.reachability.shortest_hops == 2, "bfs hops");
    check(result.reachability.nodes == std::vector<int>({1, 2, 4}), "bfs path");
}

void test_bfs_no_path() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "none 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "none 2");
    check(graph.add_node(make_node(3, "Critical Asset", "CrownJewel", 10, false, true)), "none 3");
    check(graph.add_edge(make_edge(1, 2, 0.4)), "none edge");
    const auto result = graph.analyze(1, 3, search_all(), {});
    check(!result.reachability.reachable, "bfs disconnected");
    check(!result.representative.found, "dijkstra disconnected");
    check(result.dfs.total_paths_found == 0, "dfs disconnected");
}

void test_bfs_cycle() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "cycle 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "cycle 2");
    check(graph.add_node(make_node(3, "Critical Asset", "CrownJewel", 10, false, true)), "cycle 3");
    check(graph.add_edge(make_edge(1, 2, 0.5)), "cycle e12");
    check(graph.add_edge(make_edge(2, 1, 0.5)), "cycle e21");
    check(graph.add_edge(make_edge(2, 3, 0.5)), "cycle e23");
    const auto result = graph.analyze(1, 3, search_all(), {});
    check(result.reachability.nodes == std::vector<int>({1, 2, 3}), "cycle shortest");
    check(result.dfs.total_paths_found == 1, "cycle one simple path");
}

void test_dijkstra_product() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "prod 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "prod 2");
    check(graph.add_node(make_node(3, "Server", "Internal")), "prod 3");
    check(graph.add_node(make_node(4, "Critical Asset", "CrownJewel", 80, false, true)), "prod 4");
    check(graph.add_edge(make_edge(1, 2, 0.9)), "prod high a");
    check(graph.add_edge(make_edge(2, 4, 0.9)), "prod high b");
    check(graph.add_edge(make_edge(1, 3, 0.5)), "prod low a");
    check(graph.add_edge(make_edge(3, 4, 0.5)), "prod low b");
    const auto result = graph.analyze(1, 4, search_all(), {});
    check(result.representative.nodes == std::vector<int>({1, 2, 4}), "dijkstra chooses product");
    check(std::fabs(result.representative.path_probability - 0.81) < 1e-9, "product 0.81");
    check(result.representative.target_impact == 80, "impact separate");
}

void test_dijkstra_zero() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "zero 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "zero 2");
    check(graph.add_node(make_node(3, "Critical Asset", "CrownJewel", 5, false, true)), "zero 3");
    check(graph.add_edge(make_edge(1, 3, 0.0)), "blocked direct");
    check(graph.add_edge(make_edge(1, 2, 0.5)), "via a");
    check(graph.add_edge(make_edge(2, 3, 0.5)), "via b");
    const auto result = graph.analyze(1, 3, search_all(), {});
    check(result.representative.nodes == std::vector<int>({1, 2, 3}), "p=0 skipped");
}

void test_identical_endpoints() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 40, true, true)), "same 1");
    const auto result = graph.analyze(1, 1, search_all(), {});
    check(result.reachability.reachable, "same reachable");
    check(result.reachability.shortest_hops == 0, "same hops");
    check(result.representative.path_probability == 1.0, "same product");
    check(result.dfs.total_paths_found == 1, "same one path");
}

void test_dfs_multiple_paths_and_bottleneck() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Endpoint", "DMZ", 0, true, false)), "bn 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "bn 2");
    check(graph.add_node(make_node(3, "Server", "Internal")), "bn 3");
    check(graph.add_node(make_node(4, "Critical Asset", "CrownJewel", 100, false, true)), "bn 4");
    check(graph.add_edge(make_edge(1, 2, 0.5)), "bn e12");
    check(graph.add_edge(make_edge(1, 3, 0.5)), "bn e13");
    check(graph.add_edge(make_edge(2, 4, 0.5)), "bn e24");
    check(graph.add_edge(make_edge(3, 4, 0.5)), "bn e34");
    const auto result = graph.analyze(1, 4, search_all(), {});
    check(result.dfs.total_paths_found == 2, "two paths");
    check(!result.bottlenecks.empty(), "has bottlenecks");
    // Both corridors end at 4; inbound edges each appear once.
    bool saw_inbound = false;
    for (const auto& item : result.bottlenecks) {
        if ((item.edge.from == 2 || item.edge.from == 3) && item.edge.to == 4) {
            check(item.path_count == 1, "inbound path count");
            saw_inbound = true;
        }
    }
    check(saw_inbound, "inbound bottleneck present");
}

void test_dfs_limits() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "lim 1");
    check(graph.add_node(make_node(2, "Server", "Internal")), "lim 2");
    check(graph.add_node(make_node(3, "Critical Asset", "CrownJewel", 10, false, true)), "lim 3");
    check(graph.add_edge(make_edge(1, 2, 0.5)), "lim e12");
    check(graph.add_edge(make_edge(2, 3, 0.5)), "lim e23");
    strix_dsa::SearchOptions shallow;
    shallow.max_depth = 1;
    shallow.max_paths = 100;
    const auto truncated = graph.analyze(1, 3, shallow, {});
    check(truncated.dfs.truncated, "depth truncates");
    check(truncated.dfs.total_paths_found == 0, "depth finds none");

    strix_dsa::SearchOptions capped;
    capped.max_depth = 10;
    capped.max_paths = 1;
    // Build a graph with two paths so max_paths=1 truncates.
    strix_dsa::Graph multi;
    check(multi.add_node(make_node(1, "Server", "Internal", 0, true, false)), "cap 1");
    check(multi.add_node(make_node(2, "Server", "Internal")), "cap 2");
    check(multi.add_node(make_node(3, "Server", "Internal")), "cap 3");
    check(multi.add_node(make_node(4, "Critical Asset", "CrownJewel", 10, false, true)), "cap 4");
    check(multi.add_edge(make_edge(1, 2, 0.5)), "cap e12");
    check(multi.add_edge(make_edge(1, 3, 0.5)), "cap e13");
    check(multi.add_edge(make_edge(2, 4, 0.5)), "cap e24");
    check(multi.add_edge(make_edge(3, 4, 0.5)), "cap e34");
    const auto capped_result = multi.analyze(1, 4, capped, {});
    check(capped_result.dfs.total_paths_found == 1, "path cap keeps one");
    check(capped_result.dfs.truncated, "path cap truncates");
}

void test_scenario_disable_edge() {
    strix_dsa::Graph graph;
    check(graph.add_node(make_node(1, "Server", "Internal", 0, true, false)), "sc 1");
    check(graph.add_node(make_node(2, "Critical Asset", "CrownJewel", 50, false, true)), "sc 2");
    check(graph.add_edge(make_edge(1, 2, 0.8)), "sc edge");
    strix_dsa::Scenario scenario;
    scenario.disabled_edges.emplace_back(1, 2);
    const auto result = graph.analyze(1, 2, search_all(), scenario);
    check(!result.reachability.reachable, "disabled blocks bfs");
    check(!result.representative.found, "disabled blocks dijkstra");
}

void test_empty_graph() {
    strix_dsa::Graph graph;
    const auto result = graph.analyze(1, 2, search_all(), {});
    check(!result.reachability.reachable, "empty unreachable");
    check(!result.representative.found, "empty no dijkstra");
}

}  // namespace

int main() {
    test_bfs_shortest();
    test_bfs_no_path();
    test_bfs_cycle();
    test_dijkstra_product();
    test_dijkstra_zero();
    test_identical_endpoints();
    test_dfs_multiple_paths_and_bottleneck();
    test_dfs_limits();
    test_scenario_disable_edge();
    test_empty_graph();

    if (failures == 0) {
        std::cout << "All Strix DSA engine tests passed.\n";
        return 0;
    }
    std::cerr << failures << " test assertion(s) failed.\n";
    return 1;
}
