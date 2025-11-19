# 📚 Strix Prompt Modules

## 🎯 Overview

Prompt modules are specialized knowledge packages that enhance Strix agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each module provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## 🏗️ Architecture

### How Prompts Work

When an agent is created, it can load up to 5 specialized prompt modules relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized modules
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    prompt_modules="authentication_jwt,business_logic"
)
```

The modules are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand.

---

## 📁 Module Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Advanced testing techniques for core vulnerability classes like authentication bypasses, business logic flaws, and race conditions |
| **`/frameworks`** | Specific testing methods for popular frameworks e.g. Django, Express, FastAPI, and Next.js |
| **`/technologies`** | Specialized techniques for third-party services such as Supabase, Firebase, Auth0, and payment gateways |
| **`/protocols`** | Protocol-specific testing patterns for GraphQL, WebSocket, OAuth, and other communication standards |
| **`/cloud`** | Cloud provider security testing for AWS, Azure, GCP, and Kubernetes environments |
| **`/reconnaissance`** | Advanced information gathering and enumeration techniques for comprehensive attack surface mapping |
| **`/custom`** | Community-contributed modules for specialized or industry-specific testing scenarios |

---

## 🎨 Creating New Modules

### What Should a Module Contain?

A good prompt module is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases

Modules use XML-style tags for structure and focus on deep, specialized knowledge that significantly enhances agent capabilities for that specific context.

---

## 🤝 Contributing

Community contributions are more than welcome — contribute new modules via [pull requests](https://github.com/usestrix/strix/pulls) or [GitHub issues](https://github.com/usestrix/strix/issues) to help expand the collection and improve extensibility for Strix agents.

---

> [!NOTE]
> **Work in Progress** - We're actively expanding the prompt module collection with specialized techniques and new categories.
