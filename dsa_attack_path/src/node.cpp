#include "strix_dsa/node.hpp"

namespace strix_dsa {

Node::Node(int id, const std::string& name, const std::string& type, const std::string& zone,
           int impact, bool is_entry_point, bool is_crown_jewel)
    : id_(id),
      name_(name),
      type_(type),
      zone_(zone),
      impact_(impact),
      is_entry_point_(is_entry_point),
      is_crown_jewel_(is_crown_jewel) {}

int Node::id() const { return id_; }
const std::string& Node::name() const { return name_; }
const std::string& Node::type() const { return type_; }
const std::string& Node::zone() const { return zone_; }
int Node::impact() const { return impact_; }
bool Node::is_entry_point() const { return is_entry_point_; }
bool Node::is_crown_jewel() const { return is_crown_jewel_; }

void Node::set_impact(int impact) { impact_ = impact; }
void Node::set_zone(const std::string& zone) { zone_ = zone; }
void Node::set_is_entry_point(bool entry) { is_entry_point_ = entry; }
void Node::set_is_crown_jewel(bool crown) { is_crown_jewel_ = crown; }

}  // namespace strix_dsa
