#include "strix_dsa/edge.hpp"

namespace strix_dsa {

Edge::Edge(int from, int to, const std::string& protocol, RelationType relation,
           double probability_override, bool relation_inferred, EdgeStatus baseline_status)
    : from_(from),
      to_(to),
      protocol_(protocol),
      relation_(relation),
      relation_inferred_(relation_inferred),
      probability_override_(probability_override),
      baseline_status_(baseline_status) {}

int Edge::from() const { return from_; }
int Edge::to() const { return to_; }
const std::string& Edge::protocol() const { return protocol_; }
RelationType Edge::relation() const { return relation_; }
bool Edge::relation_inferred() const { return relation_inferred_; }
double Edge::probability_override() const { return probability_override_; }
bool Edge::has_probability_override() const { return probability_override_ >= 0.0; }
EdgeStatus Edge::baseline_status() const { return baseline_status_; }

void Edge::set_protocol(const std::string& protocol) { protocol_ = protocol; }
void Edge::set_relation(RelationType relation) { relation_ = relation; }
void Edge::set_relation_inferred(bool inferred) { relation_inferred_ = inferred; }
void Edge::set_probability_override(double probability) { probability_override_ = probability; }
void Edge::set_baseline_status(EdgeStatus status) { baseline_status_ = status; }

}  // namespace strix_dsa
