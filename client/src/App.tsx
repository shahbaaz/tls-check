import { useState } from "react";
import type { SubmitEvent } from "react";
import type { CheckResponse, ErrorResponse } from "../../server/src/types.ts";

export function App() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ host: domain }),
      });
      if (res.ok) {
        setResult((await res.json()) as CheckResponse);
      } else {
        const body = (await res.json().catch(() => null)) as ErrorResponse | null;
        setError(body?.error ?? `Request failed (${res.status})`);
      }
    } catch {
      setError("Couldn't reach the server");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <h1>TLS Check</h1>
      <form onSubmit={onSubmit}>
        <label htmlFor="domain">Domain</label>
        <div className="input-row">
          <div className="input-group">
            <span className="prefix">https://</span>
            <input
              id="domain"
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <button type="submit" disabled={loading}>
            {loading ? "Checking..." : "Check"}
          </button>
        </div>
      </form>

      {error && <p role="alert">{error}</p>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </main>
  );
}
