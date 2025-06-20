# Mermaid Diagram Test

This page tests Mermaid diagram rendering in GitHub Wiki.

## Simple Graph

```mermaid
graph TD
    A[Start] --> B{Is it working?}
    B -->|Yes| C[Great!]
    B -->|No| D[Fix it]
    D --> B
```

## Sequence Diagram

```mermaid
sequenceDiagram
    participant A as User
    participant B as System
    A->>B: Request
    B-->>A: Response
```

## Flowchart

```mermaid
flowchart LR
    A[Input] --> B[Process]
    B --> C[Output]
```

If these diagrams don't render, check:
1. GitHub Wiki Mermaid support is enabled
2. Syntax is correct
3. No unsupported features are used
