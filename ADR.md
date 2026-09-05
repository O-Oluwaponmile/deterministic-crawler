# Deterministic Crawler — Architecture Decisions

---
## ADR-001 — no `is_raw` parameter in `get_page()`
- **Status**: Rejected
- **Decision**: Refactoring `get_page()` function to accept `is_raw` as a parameter to determine whether `source` wants to be passed directly as raw text string as a third fallback for fetching content to summarize. 
- **Reasoning**: Scanning and logging threats before attempting summary isn't just summary with extra steps, it is to detect what an llm crawing a page would otherwise have taken as raw input since it can read a website structure and DOM. Build 2 is built around the idea of "safer" navigation for llms/agents that are tasked to fetch the content of a page. Not for scenarios where you just want a simple summary of raw text. It is the reason we have a `get_page()` function in the first place, and as it implies, we attempt to fetch a page not become a middle man for raw text inputs. 


---
## ADR-002 — rename `SecurityResult` to `SummarizeOutcome`
- **Status**: Adopted
- **Decision**: Renamed the enum to match more closely to what is actually logged 
- **Reasoning**: `SecuirtyResult` is a very bold claim, even if it's just a naming convention. It implies a level of capability to which we have not implemented. It directly or indirectly claims that the pattern matching level implementation is enough to validate and input as secure or not which would contradict or overqualify our stated limitation for threat detection. 


---

## ADR-003 — refector `validate_output_integrity()` to use regex family based matching
- **Status**: Adopted
- **Decision**: Replace the literal pattern matching with family based regex matching just like `scan_threats()`
- **Reasoning**: Implementing the regex family based matching for similar reasons with the ADR on why we implemented it for `scan_threats()`

**Limitation:** *Family-based matching still detects string presence, not semantic role. It cannot distinguish the model reporting a blocked/attempted injection from executing one. Closing this would require semantic/intent analysis, out of scope for Build 2. Ratio-based justification: benign summaries are unlikely to incidentally contain compromise-indicator phrasing, so the false-negative-on-reported-attempts case is accepted, not solved.*

---