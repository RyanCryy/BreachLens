import { describe, it } from "vitest";
import fc from "fast-check";
import { templateOutcome } from "../netlify/functions/chat.js";
import { STATUS } from "../netlify/functions/lib/recheck.js";

// Property-based test for chat outcome templating.
//
// Design property (finding-recheck, Property 7):
//   For ANY re-checked finding (its Finding_Id and human-readable title) and ANY
//   Recheck_Status returned by the router, the chat outcome reply contains the status
//   wording mandated for that value ("resolved" for resolved, "still present" for
//   unresolved, "could not be confirmed" for indeterminate) and contains BOTH the
//   finding's Finding_Id and its human-readable title.
//
//   Validates: Requirements 8.1, 8.2
//
// templateOutcome() is the deterministic, LLM-free reply builder used by the chat path.
// It is a pure function of (findingId, title, status, routerMessage), so the property is
// exercised directly with generated inputs — no network, no mocks.

// The status wording mandated by Requirement 8.1 for each Recheck_Status value.
const MANDATED_WORDING = {
  [STATUS.RESOLVED]: "resolved", // template emits "looks resolved"
  [STATUS.UNRESOLVED]: "still present",
  [STATUS.INDETERMINATE]: "could not be confirmed",
};

describe("Feature: finding-recheck, Property 7: Chat outcome replies are templated faithfully from the router status", () => {
  it("reply contains the mandated status wording and names the finding by both Finding_Id and title, for any inputs", () => {
    fc.assert(
      fc.property(
        // arbitrary non-empty findingId
        fc.string({ minLength: 1 }).filter((s) => s.length > 0),
        // arbitrary non-empty title (trimmed non-empty so it survives templating)
        fc.string({ minLength: 1 }).filter((s) => s.trim().length > 0),
        // status drawn from the three Recheck_Status values
        fc.constantFrom(STATUS.RESOLVED, STATUS.UNRESOLVED, STATUS.INDETERMINATE),
        // arbitrary router message (appended for context)
        fc.string(),
        (findingId, title, status, routerMessage) => {
          const reply = templateOutcome(findingId, title, status, routerMessage);

          // Must contain the mandated status wording for this value (Requirement 8.1).
          const wording = MANDATED_WORDING[status];
          if (!reply.includes(wording)) {
            throw new Error(
              `reply missing mandated wording "${wording}" for status ${status}: ${JSON.stringify(reply)}`
            );
          }

          // Indeterminate replies must also invite the user to retry (Requirement 8.4).
          if (status === STATUS.INDETERMINATE && !/again/i.test(reply)) {
            throw new Error(
              `indeterminate reply missing retry invitation: ${JSON.stringify(reply)}`
            );
          }

          // Must name the finding by both its Finding_Id and its title (Requirement 8.2).
          if (!reply.includes(findingId)) {
            throw new Error(
              `reply missing findingId ${JSON.stringify(findingId)}: ${JSON.stringify(reply)}`
            );
          }
          if (!reply.includes(title.trim())) {
            throw new Error(
              `reply missing title ${JSON.stringify(title.trim())}: ${JSON.stringify(reply)}`
            );
          }
        }
      ),
      { numRuns: 200 }
    );
  });
});
