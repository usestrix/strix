#ifndef STRIX_DSA_NODE_HPP
#define STRIX_DSA_NODE_HPP

#include <string>

namespace strix_dsa {

// A node is a host or service in the directed access graph.
class Node {
public:
    Node(int id, const std::string& name, const std::string& type, const std::string& zone,
         int impact, bool is_entry_point = false, bool is_crown_jewel = false);

    int id() const;
    const std::string& name() const;
    const std::string& type() const;
    const std::string& zone() const;
    int impact() const;
    bool is_entry_point() const;
    bool is_crown_jewel() const;

    void set_impact(int impact);
    void set_zone(const std::string& zone);
    void set_is_entry_point(bool entry);
    void set_is_crown_jewel(bool crown);

private:
    int id_;
    std::string name_;
    std::string type_;
    std::string zone_;
    int impact_;
    bool is_entry_point_;
    bool is_crown_jewel_;
};

}  // namespace strix_dsa

#endif
