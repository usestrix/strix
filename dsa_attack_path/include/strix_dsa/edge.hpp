#ifndef STRIX_DSA_EDGE_HPP
#define STRIX_DSA_EDGE_HPP

#include "strix_dsa/types.hpp"

#include <string>

namespace strix_dsa {

// Directed access relationship. Probability is a simulation assumption used to
// rank modeled traversal, not a real-world exploit probability.
class Edge {
public:
    Edge(int from, int to, const std::string& protocol = "TCP/Generic",
         RelationType relation = RelationType::Unclassified, double probability_override = -1.0,
         bool relation_inferred = false, EdgeStatus baseline_status = EdgeStatus::Active);

    int from() const;
    int to() const;
    const std::string& protocol() const;
    RelationType relation() const;
    bool relation_inferred() const;
    double probability_override() const;
    bool has_probability_override() const;
    EdgeStatus baseline_status() const;

    void set_protocol(const std::string& protocol);
    void set_relation(RelationType relation);
    void set_relation_inferred(bool inferred);
    void set_probability_override(double probability);
    void set_baseline_status(EdgeStatus status);

private:
    int from_;
    int to_;
    std::string protocol_;
    RelationType relation_;
    bool relation_inferred_;
    double probability_override_;  // < 0 means use the probability table
    EdgeStatus baseline_status_;
};

}  // namespace strix_dsa

#endif
