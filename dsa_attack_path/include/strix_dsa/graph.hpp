#ifndef STRIX_DSA_GRAPH_HPP
#define STRIX_DSA_GRAPH_HPP

#include "strix_dsa/edge.hpp"
#include "strix_dsa/node.hpp"
#include "strix_dsa/types.hpp"

#include <string>
#include <vector>

namespace strix_dsa {

class Graph {
public:
    bool add_node(const Node& node);
    bool add_edge(const Edge& edge);
    bool node_exists(int id) const;
    const Node* get_node(int id) const;
    const std::vector<Node>& nodes() const;
    const std::vector<Edge>& edges() const;

    // Load a synthetic topology file. Returns false on I/O or parse errors.
    bool load_from_file(const std::string& filename);

    // Read-only analysis. Scenario overrides do not mutate the baseline graph.
    AnalysisResult analyze(int start_id, int target_id, const SearchOptions& options,
                           const Scenario& scenario) const;

private:
    std::vector<Node> nodes_;
    std::vector<Edge> edges_;
};

}  // namespace strix_dsa

#endif
