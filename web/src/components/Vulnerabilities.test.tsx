import { describe, expect, test } from "bun:test";
import { renderToString } from "react-dom/server";
import { parseFinding, type Finding } from "../lib/findings";
import { sampleExplanation, sampleFinding } from "../lib/findings.fixtures";
import { FindingDetailView, FindingsListBody, FindingsTable, ReadApiNotice, TierBadge } from "./Vulnerabilities";

function finding(overrides: Record<string, unknown> = {}): Finding {
  const f = parseFinding({ ...sampleFinding, ...overrides });
  if (!f) throw new Error("bad fixture");
  return f;
}

describe("Vulnerabilities components", () => {
  test("tier badges", () => {
    expect(renderToString(<TierBadge tier="P1" />)).toContain('class="tier tier-P1"');
    expect(renderToString(<TierBadge tier={null} />)).toContain("Unscored");
  });

  test("table lists score, tier, vuln id, purl, reachability and reason", () => {
    const html = renderToString(
      <FindingsTable findings={[finding(), finding({ id: 8, risk: null, status: "vex_not_affected", reachability: "imported" })]} />,
    );
    expect(html).toContain("tier-P1");
    expect(html).toContain(">76<");
    expect(html).toContain('href="/vulnerabilities/7"');
    expect(html).toContain("CVE-2022-32149");
    expect(html).toContain("pkg:golang/golang.org/x/text@v0.3.7");
    expect(html).toContain("Called");
    expect(html).toContain("KEV override");
    expect(html).toContain("Not scored yet");
    expect(html).toContain("Not affected (VEX)");
    expect(html).not.toContain("style=");
  });

  test("empty and disabled states", () => {
    expect(renderToString(<FindingsTable findings={[]} />)).toContain("No findings match");
    const disabled = renderToString(<FindingsListBody list={{ state: "disabled", message: "No API resource matches this path." }} />);
    expect(disabled).toContain("Read API disabled");
    expect(disabled).toContain("AEGISFLOW_DEV_READONLY_API");
    expect(disabled).toContain('role="status"');
    const err = renderToString(<ReadApiNotice state="error" message="boom" />);
    expect(err).toContain('role="alert"');
    expect(err).toContain("boom");
    expect(renderToString(<ReadApiNotice state="weird" message="m" />)).toContain("Unavailable");
    expect(renderToString(<FindingsListBody list={{ status: "loading" }} />)).toContain("Loading findings…");
    expect(renderToString(<FindingsListBody list={{ state: "ok", value: { findings: [finding()], nextCursor: "" } }} />)).toContain(
      "findings-table",
    );
  });

  test("detail view shows the factor table from the risk explanation", () => {
    const html = renderToString(
      <FindingDetailView
        finding={finding({
          vulnerability: { ...sampleFinding.vulnerability, summary: "Denial of service in language tag parsing" },
          risk: { ...sampleFinding.risk, explanation: sampleExplanation },
        })}
      />,
    );
    expect(html).toContain("Risk explanation");
    expect(html).toContain("factors-table");
    expect(html).toContain(">cvss<");
    expect(html).toContain("+30");
    expect(html).toContain("CVSS v3.1");
    expect(html).toContain("symbol called");
    expect(html).toContain("kev-override");
    expect(html).toContain("(direct)");
    expect(html).toContain("GO-2022-1059");
    expect(html).toContain("v0.3.8");
    expect(html).toContain("Denial of service");
    expect(html).toContain("aegisflow-risk/v1");
    expect(html).not.toContain("style=");
  });

  test("detail view of an unscored finding", () => {
    const html = renderToString(
      <FindingDetailView finding={finding({ risk: null, vulnerability: null, component: null, fixedVersions: [], tools: [] })} />,
    );
    expect(html).toContain("has not been scored yet");
    expect(html).toContain("x/text DoS");
    expect(html).toContain("Unscored");
  });
});
