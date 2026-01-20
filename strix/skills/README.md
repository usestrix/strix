# 📚 Strix Skills

## 🎯 Overview

Skills are specialized knowledge packages that enhance Strix agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## 🏗️ Architecture

### How Skills Work

When an agent is created, it can load up to 5 specialized skills relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized skills
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    skills="authentication_jwt,business_logic"
)
```

The skills are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand.

---

## 📁 Skill Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Advanced testing techniques for core vulnerability classes like authentication bypasses, business logic flaws, and race conditions |
| **`/frameworks`** | Specific testing methods for popular frameworks e.g. Django, Express, FastAPI, and Next.js |
| **`/technologies`** | Specialized techniques for third-party services such as Supabase, Firebase, Auth0, and payment gateways |
| **`/protocols`** | Protocol-specific testing patterns for GraphQL, WebSocket, OAuth, and other communication standards |
| **`/cloud`** | Cloud provider security testing for AWS, Azure, GCP, and Kubernetes environments |
| **`/reconnaissance`** | Advanced information gathering and enumeration techniques for comprehensive attack surface mapping |
| **`/custom`** | Community-contributed skills for specialized or industry-specific testing scenarios |

---

## 🎨 Creating New Skills

### What Should a Skill Contain?

A good skill is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases
- **YAML frontmatter** - `name` and `description` fields for skill metadata

Skills focus on deep, specialized knowledge to significantly enhance agent capabilities. They are dynamically injected into agent context when needed.

---

## 🤝 Contributing

Community contributions are more than welcome — contribute new skills via [pull requests](https://github.com/usestrix/strix/pulls) or [GitHub issues](https://github.com/usestrix/strix/issues) to help expand the collection and improve extensibility for Strix agents.

---

> [!NOTE]
> **Work in Progress** - We're actively expanding the skills collection with specialized techniques and new categories.
