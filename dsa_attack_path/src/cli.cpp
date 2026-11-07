#include "strix_dsa/graph.hpp"

#include <algorithm>
#include <iostream>
#include <string>

namespace {

void print_path(const std::vector<int>& nodes) {
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        if (i) std::cout << " -> ";
        std::cout << nodes[i];
    }
}

void usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " <topology.txt> <start_id> <target_id> [max_depth] [max_paths]\n"
        << "\n"
        << "SIMULATION ONLY — analyzes a labeled synthetic directed graph.\n"
        << "Output is modeled reachability / path ranking, NOT real pentest results.\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }

    const std::string topology = argv[1];
    const int start_id = std::stoi(argv[2]);
    const int target_id = std::stoi(argv[3]);

    strix_dsa::SearchOptions options;
    if (argc >= 5) options.max_depth = static_cast<std::size_t>(std::stoul(argv[4]));
    if (argc >= 6) options.max_paths = static_cast<std::size_t>(std::stoul(argv[5]));

    strix_dsa::Graph graph;
    if (!graph.load_from_file(topology)) return 1;
    if (!graph.node_exists(start_id) || !graph.node_exists(target_id)) {
        std::cerr << "[!] Start or target node not found in simulated topology.\n";
        return 1;
    }

    const strix_dsa::AnalysisResult result = graph.analyze(start_id, target_id, options, {});

    std::cout << "=== Strix DSA Attack Path (MODELED / SIMULATED DATA) ===\n";
    std::cout << "Disclaimer: MODELED ATTACK GRAPH — not a confirmed multi-hop "
              << "exploit chain.\n"
              << "Algorithm output on labeled topology; not live pentest proof.\n\n";
    std::cout << "Start: " << start_id << "  Target: " << target_id << "\n";
    std::cout << "BFS reachable: " << (result.reachability.reachable ? "yes" : "no");
    if (result.reachability.reachable) {
        std::cout << "  hops=" << result.reachability.shortest_hops << "  path=";
        print_path(result.reachability.nodes);
    }
    std::cout << "\n";

    std::cout << "DFS simple paths: " << result.dfs.total_paths_found
              << (result.dfs.truncated ? " (TRUNCATED)" : "") << "\n";

    if (result.representative.found) {
        std::cout << "Dijkstra representative path (max product / min -log p): ";
        print_path(result.representative.nodes);
        std::cout << "\n  modeled path product: " << result.representative.path_probability
                  << "  target impact: " << result.representative.target_impact << "\n";
        if (result.representative.has_weakest) {
            std::cout << "  weakest link: " << result.representative.weakest.from << " -> "
                      << result.representative.weakest.to
                      << " p=" << result.representative.weakest.probability << "\n";
        }
    } else {
        std::cout << "Dijkstra: no traversable path under current probabilities.\n";
    }

    std::cout << "\nTop bottlenecks (by crown-jewel reach + path frequency):\n";
    const std::size_t limit = std::min<std::size_t>(5, result.bottlenecks.size());
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& item = result.bottlenecks[i];
        std::cout << "  " << item.edge.from << " -> " << item.edge.to
                  << "  paths=" << item.path_count << " (" << item.path_share_percent << "%)"
                  << "  jewels=" << item.crown_jewels_count << "\n";
    }
    if (result.bottlenecks.empty()) std::cout << "  (none)\n";

    std::cout << "\nCrown jewels:\n";
    for (const auto& jewel : result.crown_jewels) {
        std::cout << "  #" << jewel.id << " " << jewel.name << " impact=" << jewel.impact
                  << " reachable=" << (jewel.reachable ? "yes" : "no");
        if (jewel.reachable) std::cout << " hops=" << jewel.shortest_hops;
        std::cout << "\n";
    }

    return 0;
}
