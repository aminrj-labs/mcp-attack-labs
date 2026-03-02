# [Post Title: Attack Technique — What I Learned]

_[One-sentence hook. Why does this attack matter?]_

---

## Background

[2–3 paragraphs of context. What is the system being attacked? Why do people use it?
What threat model does this attack fit into?]

---

## How the Attack Works

[Technical explanation of the mechanism. Link to any original research or CVEs.]

### The Core Idea

[Distilled explanation — the "aha" moment for the reader.]

### What the Victim Sees

[What does a normal user observe? What's hidden from them?]

---

## Lab Architecture

```
[ASCII diagram of the lab setup]

Component A  ←→  Component B  ←→  Component C
                              ↓
                         Attacker receiver
```

| Component | Role |
|-----------|------|
| [name] | [description] |
| [name] | [description] |

---

## Setup

[Brief setup steps with code blocks. Link to the lab README for full detail.]

```bash
[key commands]
```

---

## Attempts

### Attempt 1 — [What I tried first]

[What I expected. What actually happened. Why it didn't work.]

### Attempt 2 — [What I changed]

[The adjustment. Why I thought it would help.]

### Successful Run

[What the working configuration looked like. Output snippet showing success.]

```
[Terminal output showing the attack succeeding]
```

---

## What This Demonstrates

[3–5 bullet points on the broader security implications beyond this specific lab.]

- **[Point 1]:** [Explanation]
- **[Point 2]:** [Explanation]
- **[Point 3]:** [Explanation]

---

## Defensive Takeaways

[Practical advice for defenders and developers.]

- **[Principle]:** [What to do differently]
- **[Principle]:** [What to do differently]
- **[Principle]:** [What to do differently]

---

## References

- [Original research or vulnerability report](url)
- [Relevant tool or scanner](url)
- [Further reading](url)
